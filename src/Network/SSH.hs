{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}
module Network.SSH
  (
  ) where
import Control.Concurrent
import Control.Concurrent.MVar
import Control.Exception
import Control.Monad
import Data.ByteString (ByteString)
import Foreign.Ptr (nullPtr)
import qualified Network.SSH.Primitive as P
import qualified Bindings.Libssh2 as C
import System.Posix.Types (Fd(..))
import System.IO.Unsafe
import Network.Socket
  ( Socket(..)
  , AddrInfoFlag(..)
  , SocketType(Stream)
  , connect
  , socket
  , close
  , defaultHints
  , addrFlags
  , addrFamily
  , addrAddress
  , getAddrInfo
  )

#if defined __GLASGOW_HASKELL__ && __GLASGOW_HASKELL__ >= 708
import GHC.Event

{-
sshManager :: EventManager
sshManager = unsafePerformIO new
{-# NOINLINE sshManager #-}
-}

useNonBlocking :: Bool
useNonBlocking = True

#else
useNonBlocking :: Bool
useNonBlocking = False
#endif

sshLibInit :: ()
sshLibInit = unsafePerformIO $ P.initializeSSH P.normal
{-# NOINLINE sshLibInit #-}

data SshConnection = SshConnection
  { sshConnectionSession :: !C.Session
  , sshConnectionSocket  :: !Socket
  , sshConnectionFd      :: !Fd
  }

data Channel = Channel
  { channelPtr     :: !C.Channel
  , channelSession :: !C.Session
  , channelFd      :: !Fd
  }

class HasSession a where
  session :: a -> C.Session

class HasFd a where
  fd :: a -> Fd

instance HasSession SshConnection where
  session = sshConnectionSession

instance HasSession Channel where
  session = channelSession

instance HasFd SshConnection where
  fd = sshConnectionFd

instance HasFd Channel where
  fd = channelFd

instance P.IsSession SshConnection where
  usingSession s = P.usingSession (sshConnectionSession s)

makeSession :: IO C.Session
makeSession = sshLibInit `seq` P.createRawSession

connect :: String -> Int -> IO SshConnection
connect host port = do
  let hints = defaultHints { addrFlags = [ AI_ADDRCONFIG, AI_CANONNAME ] }
  addrs <- getAddrInfo (Just hints) (Just host) (Just $ show port)
  case addrs of
    [] -> undefined
    (addr:_) -> do
      sock@(MkSocket fd _ _ _ _) <- socket (addrFamily addr) Stream 0
      Network.Socket.connect sock (addrAddress addr)
      s <- makeSession
      r <- P.handshake s sock
      P.sessionSetBlocking s (not useNonBlocking)
      return $ SshConnection s sock (Fd fd)

disconnect :: SshConnection -> IO ()
disconnect conn = do
  P.sessionDisconnect conn "Network.SSH.disconnect"
  Network.Socket.close $ sshConnectionSocket conn
  void $ C.session_free $ sshConnectionSession conn

wouldBlock :: C.SshError -> Bool
wouldBlock = (== C.WouldBlock)

allGood :: C.SshError -> Bool
allGood = (== C.NoError)

checkErr :: C.SshError -> a -> Either C.SshError a
checkErr c x = if allGood c then Right x else Left c

handleBlockingEvent :: (HasSession p, HasFd p) => p -> (a -> Maybe C.SshError) -> IO a -> IO a
handleBlockingEvent p fIn m = do
  let s = session p
      fd' = fd p
  r <- m
  if useNonBlocking && (maybe False wouldBlock $ fIn r)
    then do
      dirs <- P.sessionBlockDirections s
      case dirs of
        C.Inbound -> threadWaitRead fd'
        C.Outbound -> threadWaitWrite fd'
        C.Bidirectional -> threadWaitRead fd' >> threadWaitWrite fd'
      handleBlockingEvent p fIn m
    else return r

leftCheck :: Either a b -> Maybe a
leftCheck (Left x) = Just x
leftCheck _ = Nothing

fstCheck :: (a, b) -> Maybe a
fstCheck = Just . fst

openSessionChannel :: SshConnection -> IO (Either C.SshError Channel)
openSessionChannel s = handleBlockingEvent s leftCheck $ do
  c@(C.Channel p) <- P.openSessionChannel s
  if p == nullPtr
    then Left <$> P.sessionLastErrorCode s
    else pure $ Right $ Channel c (session s) (fd s)

channelSetup :: SshConnection -> (Channel -> IO C.SshError) -> IO (Either C.SshError Channel)
channelSetup s f = do
  c <- openSessionChannel s
  case c of
    Left err -> return $ Left err
    Right c' -> do
      r <- handleBlockingEvent s Just $ f c'
      if allGood r
        then return $ Right c'
        else P.closeChannel (channelPtr c') >> P.freeChannel (channelPtr c') >> return (Left r)

shell :: SshConnection -> IO (Either C.SshError Channel)
shell s = channelSetup s (P.shellChannel . channelPtr)

exec :: SshConnection -> ByteString -> IO (Either C.SshError Channel)
exec s b = channelSetup s (\c -> P.execChannel (channelPtr c) b)

subsystem :: SshConnection -> ByteString -> IO (Either C.SshError Channel)
subsystem s b = channelSetup s (\c -> P.subsystemChannel (channelPtr c) b)

close :: Channel -> IO C.SshError
close c = handleBlockingEvent c Just $ P.closeChannel $ channelPtr c

send c = handleBlockingEvent c leftCheck . P.channelWrite (channelPtr c)

recv c = handleBlockingEvent c leftCheck . P.channelRead (channelPtr c)

authFromPublicKeyFile :: SshConnection
                      -> ByteString -- ^ Username
                      -> Maybe ByteString -- ^ Public key path. If libssh2 is built against OpenSSL, this option can be set to Nothing.
                      -> ByteString -- ^ Private key path
                      -> Maybe ByteString -- ^ Passphrase
                      -> IO C.SshError
authFromPublicKeyFile s u pubkey privkey mpass = handleBlockingEvent s Just $ P.authFromPublicKeyFile s u pubkey privkey mpass

testRun cmd = do
  ssh <- Network.SSH.connect "localhost" 22
  print =<< authFromPublicKeyFile ssh "ian" (Just "/Users/ian/.ssh/id_rsa.pub") "/Users/ian/.ssh/id_rsa" (Just "11690,imD")
  print =<< P.isAuthenticated ssh
  r <- exec ssh cmd
  case r of
    Left err -> do
      print =<< P.sessionLastError ssh
      print err
    Right c -> do
      reader <- newEmptyMVar
      writer <- newEmptyMVar

      forkIO $ do
        s <- recv c 10
        print s
        putMVar reader ()

      forkIO $ do
        send c "EAGLE!!!!!!!!!!!!!!!!!!!!!!!!!!\n" >>= print
        putMVar writer ()
 
      takeMVar reader
      takeMVar writer
      Network.SSH.close c
      print =<< P.freeChannel (channelPtr c)
      return ()
  disconnect ssh
  {-
  sendEof chan
  print =<< closeChannel chan
  putStrLn "Waiting for EOF?"
  print =<< waitEof chan
  let go = do
        r <- channelRead chan 1024
        case r of
          Left err -> print err
          Right str -> do
            print str
            unless (str == "") go
  go
  print =<< isEof chan
  print =<< waitChannelClose chan
  putStrLn "Status???"
  print =<< getExitStatus chan
  freeChannel chan
  -}
