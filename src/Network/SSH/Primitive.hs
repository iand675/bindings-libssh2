{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.Primitive (
  -- * SSH library setup and teardown
  initializeSSH,
  C.normal,
  C.noCrypto,
  exitSSH,
  -- * Sessions
  Session,
  IsSession(..),
  createSession,
  createRawSession,
  freeRawSassion,
  withSession,
  sessionDisconnect,
  sessionDisconnect',
  sessionBlockDirections,
  sessionLastError,
  sessionLastErrorCode,
  -- * Authentication
  handshake,
  isAuthenticated,
  listAuthSchemes,
  authFromPassword,
  authFromPublicKeyFile,
  authHostbasedFromFile,
  authPublicKeyFromMemory,
  setLocalBanner,
  getRemoteBanner,
  -- * Channel operations
  {-| The SSH protocol requires that requests for services on a remote machine be made over channels. A single SSH connection may contain multiple channels, all run simultaneously over that connection.

Each channel, in turn, represents the processing of a single service. When you invoke a process on the remote host via @openSessionChannel@, @shellChannel@, @execChannel@, or @subsystemChannel@, a channel is opened for that invocation, and all input and output relevant to that process is sent through that channel. The connection itself simply manages the packets of all of the channels that it has open.

This means that, for instance, over a single SSH connection you could execute a process, download a file via SFTP, and forward any number of ports, all (seemingly) at the same time!

Naturally, they do not occur simultaneously, but rather work in a “time-share” fashion by sharing the bandwidth of the connection.
-}
  C.Channel,
  openChannel,
  -- directTcpIpChannel,
  -- channelListener,
  -- cancelListener,
  -- acceptListener,
  openSessionChannel,
  shellChannel,
  execChannel,
  subsystemChannel,
  setEnv,
  requestPty,
  requestPtySize,
  requestX11,
  channelProcessStartup,
  channelRead,
  channelReadStdErr,
  channelRead',
  -- windowRead,
  -- receiveWindowAdjust,
  channelWrite,
  channelWriteStdErr,
  channelWrite',
  -- windowWrite,
  sessionSetBlocking,
  sessionGetBlocking,
  channelSetBlocking,
  -- sessionSetTimeout,
  -- sessionGetTimeout,
  -- handleExtendedData,
  channelFlush,
  channelFlushStdErr,
  channelFlush',
  closeChannel,
  waitChannelClose,
  freeChannel,
  getExitStatus,
  isEof,
  sendEof,
  waitEof
) where
import Control.Exception
import Control.Monad
import Data.ByteString (ByteString, packCString, useAsCString, useAsCStringLen)
import qualified Data.ByteString.Char8 as B
import Foreign.C
import Foreign.ForeignPtr
import Foreign.Marshal.Alloc
import Foreign.Ptr
import Network.Socket
import System.Exit
import qualified Bindings.Libssh2 as C
import Test.Tasty

maybeUseAsCString :: Maybe ByteString -> (CString -> IO a) -> IO a
maybeUseAsCString bs f = case bs of
  Nothing -> f nullPtr
  Just b -> useAsCString b f

boolInt :: Bool -> CInt
boolInt b = if b then 1 else 0

intBool :: CInt -> Bool
intBool = (== 1)

-- | Initialize the libssh2 functions. This typically initializes the underlying crypto library. It uses global state, and is not thread safe. You must make sure this function is not called concurrently.
initializeSSH :: C.InitFlags -> IO ()
initializeSSH = void . C.init

-- Exits the libssh2 functions and frees all memory used internally.
exitSSH :: IO ()
exitSSH = C.exit

class IsSession a where
  usingSession :: a -> (C.Session -> IO b) -> IO b

newtype Session = Session (ForeignPtr ())

instance IsSession C.Session where
  usingSession x f = f x

instance IsSession Session where
  usingSession (Session fp) f = withForeignPtr fp (f . C.Session)

-- | Creates an Session that is automatically freed when no longer in use.
-- This does not mean that the session is automatically disconnected, however.
-- For long-lived sessions, this is convenient. For more short-term sessions
-- or sessions that need prompt finalization, see @withSession@
createSession :: IO Session
createSession = do
  (C.Session ptr) <- C.session_init_ex nullFunPtr nullFunPtr nullFunPtr nullPtr
  fp <- newForeignPtr (castFunPtr C.session_free_wrapper) ptr
  return $ Session fp

createRawSession :: IO C.Session
createRawSession = C.session_init_ex nullFunPtr nullFunPtr nullFunPtr nullPtr

freeRawSassion :: C.Session -> IO ()
freeRawSassion = void . C.session_free

-- | Allocates and initializes a session, automatically freeing it after the provided function has been exited.
withSession :: (C.Session -> IO a) -> IO a
withSession = bracket
  (C.session_init_ex nullFunPtr nullFunPtr nullFunPtr nullPtr)
  C.session_free

-- | A convenience wrapper around @sessionDisconnect'@ that calls it with reason set to SSH_DISCONNECT_BY_APPLICATION and lang set to an empty string.
sessionDisconnect :: IsSession s => s
                  -> ByteString -- ^ Description
                  -> IO C.SshError
sessionDisconnect s desc = sessionDisconnect' s C.by_application desc ""

-- | Send a disconnect message to the remote host associated with session, along with a reason symbol and a verbose description.
sessionDisconnect' :: IsSession s => s
                   -> C.DisconnectReason
                   -> ByteString -- ^ Verbose disconnect reason
                   -> ByteString -- ^ Language
                   -> IO C.SshError
sessionDisconnect' s reason desc lang = usingSession s $ \s' -> fmap C.convertError $
  useAsCString lang $ \lp ->
  useAsCString desc $ \dp ->
  C.session_disconnect_ex s' reason lp dp

-- | Get a string version of the last error that occurred.
sessionLastError :: IsSession s => s -> IO ByteString
sessionLastError s = usingSession s $ \s' -> do
  (_, cstr, l) <- C.session_last_error s' 0
  B.packCStringLen (cstr, fromIntegral l)

sessionLastErrorCode :: IsSession s => s -> IO C.SshError
sessionLastErrorCode s = fmap C.convertError $ usingSession s $ C.session_last_errno

-- | Get the current directions that the underlying file descriptor is blocked on.
sessionBlockDirections :: IsSession s => s
                       -> IO C.BlockDirections
sessionBlockDirections s = usingSession s (fmap checkDirections . C.session_block_directions)
  where
    checkDirections x = case x of
      1 -> C.Inbound
      2 -> C.Outbound
      3 -> C.Bidirectional
      _ -> error ("Unsupported block direction " ++ show x)

-- | Begin transport layer protocol negotiation with the connected host.
handshake :: IsSession s => s
          -> Socket -- Connected socket descriptor. Typically a TCP connection though the protocol allows for any reliable transport and the library will attempt to use any berkeley socket.
          -> IO C.SshError
handshake s (MkSocket fd _ _ _ _) = fmap C.convertError $ usingSession s $ \s' -> C.session_handshake s' (C.Socket fd)

-- | Indicates whether or not the provided session has been successfully authenticated.
isAuthenticated :: IsSession s => s -> IO Bool
isAuthenticated s = (== 1) <$> usingSession s C.userauth_authenticated

-- | Send a SSH_USERAUTH_NONE request to the remote host. Unless the remote host is configured to accept none as a viable authentication scheme (unlikely), it will return SSH_USERAUTH_FAILURE along with a listing of what authentication schemes it does support. In the unlikely event that none authentication succeeds, this function will return an empty list. This case may be distinguished from a failing case by examining @isAuthenticated@.
listAuthSchemes :: IsSession s => s -> ByteString -> IO [ByteString]
listAuthSchemes s username = usingSession s $ \s' -> do
  r <- useAsCStringLen username $ \(up, ul) -> C.userauth_list s' up (fromIntegral ul)
  if r == nullPtr
    then return []
    else do
      p <- packCString r
      return $ B.split ',' p

-- | Attempt basic password authentication. Note that many SSH servers which appear to support ordinary password authentication actually have it disabled and use Keyboard Interactive authentication (routed via PAM or another authentication backend) instead.
authFromPassword :: IsSession s => s
                 -> ByteString -- ^ Username
                 -> ByteString -- ^ Password
                 -> IO C.SshError
authFromPassword s u p = fmap C.convertError $ usingSession s $ \s' ->
  useAsCStringLen u $ \(up, ul) ->
  useAsCStringLen p $ \(pp, pl) ->
  C.userauth_password_ex s' up (fromIntegral ul) pp (fromIntegral pl) nullFunPtr

-- | Attempt public key authentication using a PEM encoded private key file stored on disk
authFromPublicKeyFile :: IsSession s => s
                      -> ByteString -- ^ Username
                      -> Maybe ByteString -- ^ Public key path. If libssh2 is built against OpenSSL, this option can be set to Nothing.
                      -> ByteString -- ^ Private key path
                      -> Maybe ByteString -- ^ Passphrase
                      -> IO C.SshError
authFromPublicKeyFile s u pubkey privkey mpass = do
  r <- usingSession s $ \s' ->
    useAsCStringLen u $ \(up, ul) ->
    maybeUseAsCString pubkey $ \pubkeyp ->
    useAsCString privkey $ \privkeyp ->
    let f = C.userauth_publickey_fromfile_ex s' up (fromIntegral ul) pubkeyp privkeyp in
    case mpass of
      Nothing -> f nullPtr
      Just pass -> useAsCString pass f
  return $ C.convertError r

{-
TODO how does the sign_callback fit into this?
authFromPublicKey :: IsSession s => s
                  -> ByteString -- ^ Username
                  -> ByteString -- ^ Public key data
                  -> _
                  -> 
-}

-- | This is undocumented by the libssh2 library, so I don't really know what this is supposed to do.
-- Maybe it checks known hosts automatically? TODO: find out.
authHostbasedFromFile :: IsSession s => s
                      -> ByteString -- ^ Username
                      -> ByteString -- ^ Public key
                      -> ByteString -- ^ Private key
                      -> Maybe ByteString -- ^ Passphrase
                      -> ByteString -- ^ Hostname
                      -> ByteString -- ^ Local username
                      -> IO C.SshError
authHostbasedFromFile s u pubkey privkey mpass host local = do
  r <- usingSession s $ \s' ->
    useAsCStringLen u $ \(up, ul) ->
    useAsCString pubkey $ \pubkeyp ->
    useAsCString privkey $ \privkeyp ->
    useAsCStringLen host $ \(hostp, hostl) ->
    useAsCStringLen local $ \(localp, locall) ->
    let f passp = C.userauth_hostbased_fromfile_ex s' up (fromIntegral ul) pubkeyp privkeyp passp hostp (fromIntegral hostl) localp (fromIntegral locall) in
    case mpass of
      Nothing -> f nullPtr
      Just pass -> useAsCString pass f
  return $ C.convertError r

-- | Attempt public key authentication using a PEM encoded private key file stored in memory. Only supported
-- when libssh2 is backed by OpenSSL.
authPublicKeyFromMemory :: IsSession s => s
                        -> ByteString -- ^ Username
                        -> ByteString -- ^ Public key file data
                        -> ByteString -- ^ Private key file data
                        -> Maybe ByteString -- ^ Passphrase
                        -> IO C.SshError
authPublicKeyFromMemory s u pubkey privkey mpass = do
  r <- usingSession s $ \s' ->
    useAsCStringLen u $ \(up, ul) ->
    useAsCStringLen pubkey $ \(pubkeyp, pubkeyl) ->
    useAsCStringLen privkey $ \(privkeyp, privkeyl) ->
    let f = C.userauth_publickey_frommemory s' up (fromIntegral ul) pubkeyp (fromIntegral pubkeyl) privkeyp (fromIntegral privkeyl) in
    case mpass of
      Nothing -> f nullPtr
      Just pass -> useAsCString pass f
  return $ C.convertError r

{- TODO
authFromKeyboardInteractive :: IsSession s => s
                            -> ByteString -- ^ Username
                            -> 
-}

-- | Set the banner that will be sent to the remote host when the SSH session is started with @handshake@. This is optional- a banner corresponding to the protocol and libssh2 version will be sent by default.
setLocalBanner :: IsSession s => s -> ByteString -> IO C.SshError
setLocalBanner s b = usingSession s $ \s' -> do
  r <- useAsCString b $ C.session_banner_set s'
  return $ C.convertError r

-- | Once the session has been setup and @handshake@ has completed successfully, this function can be used to get the server id from the banner each server presents.
getRemoteBanner :: IsSession s => s -> IO (Maybe ByteString)
getRemoteBanner s = usingSession s $ \s' -> do
  cstr <- C.session_banner_get s'
  if cstr == nullPtr
    then return Nothing
    else Just <$> packCString cstr

-- | Establishes a generic session channel. Generally @openSessionChannel@ is what most users will want.
openChannel :: IsSession s => s
            -> ByteString -- ^ Channel type to open. Typically one of @session@, @direct-tcpip@, or @tcpip-forward@. The SSH2 Protocol allowed for additional types including local, custom channel types.
            -> Int -- ^ window size. Maximum amount of unacknowledged data remote host is allowed to send before receiving an SSH_MSG_CHANNEL_WINDOW_ADJUST packet
            -> Int -- ^ packet size. Maximum number of bytes remote host is allowed to send in a single SSH_MSG_CHANNEL_DATA or SSG_MSG_CHANNEL_EXTENDED_DATA packet.
            -> Maybe ByteString -- ^ message. Additional data as required by the selected channel type.
            -> IO C.Channel
openChannel s c ws ps msg = usingSession s $ \s' -> useAsCStringLen c $ \(cp, cl) ->
  let f = C.channel_open_ex s' cp (fromIntegral cl) (fromIntegral ws) (fromIntegral ps) in
  case msg of
    Nothing -> f nullPtr 0
    Just m -> useAsCStringLen m $ \(mp, ml) -> f mp (fromIntegral ml)

-- | Convenience function for opening a @session@ channel
openSessionChannel :: IsSession s => s -> IO C.Channel
openSessionChannel s = openChannel s "session" C.channel_window_default C.channel_packet_default Nothing

-- | Request a shell on a channel
channelProcessStartup :: C.Channel
                      -> ByteString -- ^ Type of process to startup. The SSH2 protocol currently defines @shell@, @exec@, and @subsystem@ as standard process services.
                      -> Maybe ByteString -- ^ Request specific message data to include.
                      -> IO C.SshError
channelProcessStartup c r m = fmap C.convertError $ useAsCStringLen r $ \(rp, rl) ->
  let f = C.channel_process_startup c rp (fromIntegral rl) in
  fromIntegral <$> case m of
    Nothing -> f nullPtr 0
    Just m' -> useAsCStringLen m' $ \(mp, ml) -> f mp $ fromIntegral ml

-- | Attempt to read data from an active channel stream. All channel streams have one standard I/O substream (stream_id == 0), and may have up to 2^32 extended data streams as identified by the selected stream_id. The SSH2 protocol currently defines a stream ID of 1 to be the stderr substream.
channelRead' :: C.Channel
             -> Int -- ^ Stream Id. Substream ID number (e.g. 0 for the standard stream or 1 for STDERR)
             -> Int -- ^ Number of bytes to attempt to read.
             -> IO (Either C.SshError ByteString)
channelRead' c streamId bufSize = allocaBytes bufSize $ \cstr -> do
  r <- C.channel_read_ex c (fromIntegral streamId) cstr (fromIntegral bufSize)
  if r < 0
    then return $ Left $ C.convertError $ fromIntegral r
    else Right <$> B.packCStringLen (cstr, fromIntegral r)

-- | Read bytes from the primary channel stream (STDOUT in the case of a shell or exec channel)
channelRead :: C.Channel
            -> Int -- ^ Number of bytes to attempt to read.
            -> IO (Either C.SshError ByteString)
channelRead c = channelRead' c 0

-- | Read bytes from the STDERR stream
channelReadStdErr :: C.Channel
                  -> Int -- ^ Number of bytes to attempt to read
                  -> IO (Either C.SshError ByteString)
channelReadStdErr c = channelRead' c 1

-- | Write data to a channel stream. All channel streams have one standard I/O substream (stream_id == 0), and may have up to 2^32 extended data streams as identified by the selected stream_id. The SSH2 protocol currently defines a stream ID of 1 to be the stderr substream. Most users won't need o use this. For common use cases, see @channelWrite@ and @channelWriteStderr@.
channelWrite' :: C.Channel
              -> Int -- ^ Stream to write to
              -> ByteString -- ^ Bytes to write to stream
              -> IO (Either C.SshError Int) -- ^ On success, number of bytes successfully written.
channelWrite' c streamId bs = do
  r <- B.useAsCStringLen bs $ \(p, l) ->
    C.channel_write_ex c (fromIntegral streamId) p (fromIntegral l)
  return $ if r < 0
    then Left $ C.convertError $ fromIntegral r
    else Right $ fromIntegral r

-- | Write to the primary channel stream.
channelWrite :: C.Channel
             -> ByteString -- Bytes to write
             -> IO (Either C.SshError Int) -- ^ On success, number of bytes successfully written.
channelWrite c = channelWrite' c 0

-- | Write to the STDERR channel stream
channelWriteStdErr :: C.Channel
                   -> ByteString -- Bytes to write
                   -> IO (Either C.SshError Int) -- ^ On success, number of bytes successfully written.
channelWriteStdErr c = channelWrite' c 1

-- | Set or clear blocking mode on session
sessionSetBlocking :: IsSession s => s
                   -> Bool -- ^ @True@ sets the session as blocking, @False@ for nonblocking. Note that setting the session to nonblocking can cause many operations to return @WouldBlock@, which isn't an error per se, but it does affect how to handle the results.
                   -> IO ()
sessionSetBlocking s b = usingSession s $ \s' -> C.session_set_blocking s' (boolInt b)

-- | Returns @False@ if the state of the session has previously be set to non-blocking and it returns @True@ if the state was set to blocking.
sessionGetBlocking :: IsSession s => s
                   -> IO Bool
sessionGetBlocking s = intBool <$> usingSession s C.session_get_blocking

-- | Currently this is just a short cut call to @sessionSetBlocking@, and therefore will affect the session and all channels.
channelSetBlocking :: C.Channel -> Bool -> IO ()
channelSetBlocking c b = C.channel_set_blocking c (boolInt b)

-- | Flush primary stream on channel
channelFlush :: C.Channel -> IO C.SshError
channelFlush c = channelFlush' c 0

-- | Flush STDERR stream of a channel
channelFlushStdErr :: C.Channel -> IO C.SshError
channelFlushStdErr c = channelFlush' c 1

-- | Flush a channel
channelFlush' :: C.Channel
              -> Int -- ^ Specific substream number to flush. Groups of substreams may be flushed by passing on of the following Constants. 
                     -- LIBSSH2_CHANNEL_FLUSH_EXTENDED_DATA: Flush all extended data substreams 
                     -- LIBSSH2_CHANNEL_FLUSH_ALL: Flush all substreams
              -> IO C.SshError
channelFlush' c = fmap C.convertError . C.channel_flush_ex c . fromIntegral

-- | Open a shell channel. This uses the login shell of the specified
-- user on the remote host.
shellChannel :: C.Channel -> IO C.SshError
shellChannel c = channelProcessStartup c "shell" Nothing

-- | Execute a single command on the remote host.
execChannel :: C.Channel
            -> ByteString -- ^ The command to execute
            -> IO C.SshError
execChannel c = channelProcessStartup c "exec" . Just

-- | Initialize the specified subsystem on the given channel
subsystemChannel :: C.Channel -> ByteString -> IO C.SshError
subsystemChannel c = channelProcessStartup c "subsystem" . Just

-- | Set an environment variable in the remote channel's process space. Note that this does not make sense for all channel types and may be ignored by the server despite returning success.
setEnv :: C.Channel
       -> ByteString -- ^ Name of environment variable to set on the remote channel instance.
       -> ByteString -- ^ Value to set varname to.
       -> IO C.SshError
setEnv c k v = fmap C.convertError $
  useAsCStringLen k $ \(kp, kl) ->
  useAsCStringLen v $ \(vp, vl) ->
  C.channel_setenv_ex c kp (fromIntegral kl) vp (fromIntegral vl)

-- | Request a PTY on an established channel. Note that this does not make sense for all channel types and may be ignored by the server despite returning success.
requestPty :: C.Channel
           -> ByteString -- ^ Terminal emulation (e.g. vt102, ansi, etc...)
           -> Maybe ByteString -- ^ Terminal mode modifier values
           -> Int -- ^ Width of pty in characters
           -> Int -- ^ Height of pty in characters
           -> Int -- ^ Width of pty in pixels
           -> Int -- ^ Height of pty in pixels
           -> IO C.SshError
requestPty c t m w h wpx hpx = fmap C.convertError $
  useAsCStringLen t $ \(tp, tl) ->
  let f (mp, ml) = C.channel_request_pty_ex c tp (fromIntegral tl) mp (fromIntegral ml) (fromIntegral w) (fromIntegral h) (fromIntegral wpx) (fromIntegral hpx) in
  case m of
    Nothing -> f (nullPtr, 0 :: Int)
    Just m' -> useAsCStringLen m' f

-- | Request that a PTY established by the @requestPty@ call is resized to the given width and height. It's acceptable to pass in 0 for pixel sizes if it doesn't matter.
requestPtySize :: C.Channel
               -> Int -- ^ Width of pty in characters
               -> Int -- ^ Height of pty in characters
               -> Int -- ^ Width of pty in pixels
               -> Int -- ^ Height of pty in pixels
               -> IO C.SshError
requestPtySize c w h wpx hpx = fmap C.convertError $
  C.channel_request_pty_size_ex c (fromIntegral w) (fromIntegral h) (fromIntegral wpx) (fromIntegral hpx)

-- | Request an X11 forwarding on channel. To use X11 forwarding, libssh2_session_callback_set, must first be called to set LIBSSH2_CALLBACK_X11. This callback will be invoked when the remote host accepts the X11 forwarding.
requestX11 :: C.Channel
           -> Bool -- ^ @True@ to only forward a single connection, usually @False@ is used.
           -> Maybe ByteString -- ^ X11 authentication protocol to use
           -> Maybe ByteString -- ^ A hex encoded auth cookie
           -> Int -- ^ The XLL screen to forward
           -> IO C.SshError
requestX11 c singleConn mAuthProto mAuthCookie screenNumber = fmap C.convertError $
  maybeUseAsCString mAuthProto $ \app ->
  maybeUseAsCString mAuthCookie $ \acp ->
  C.channel_x11_req_ex c (boolInt singleConn) app acp (fromIntegral screenNumber)

-- | Close an active data channel. In practice this means sending an SSH_MSG_CLOSE packet to the remote host which serves as instruction that no further data will be sent to it. The remote host may still send data back until it sends its own close message in response. To wait for the remote end to close its connection as well, follow this command with @waitChannelClose@.
closeChannel :: C.Channel -> IO C.SshError
closeChannel = fmap C.convertError . C.channel_close

-- | Enter a temporary blocking state until the remote host closes the named channel. Typically sent after @closeChannel@ in order to examine the exit status.
waitChannelClose :: C.Channel -> IO C.SshError
waitChannelClose = fmap C.convertError . C.channel_wait_closed

-- | Release all resources associated with a channel stream. If the channel has not yet been closed with @closeChannel@, it will be called automatically so that the remote end may know that it can safely free its own resources.
freeChannel :: C.Channel -> IO C.SshError
freeChannel = fmap C.convertError . C.channel_free

-- | Returns the exit code raised by the process running on the remote host at the other end of the named channel. Note that the exit status may not be available if the remote end has not yet set its status to closed. For example, attempting to read the exit status of a still running process on a non-closed channel or a channel that had a still running process will return @ExitSuccess@. To avoid this, ensure that @isEof@ for the current channel is True and that the channel has actually closed.
getExitStatus :: C.Channel -> IO ExitCode
getExitStatus c = do
  status <- C.channel_get_exit_status c
  return $ if status == 0
           then ExitSuccess
           else ExitFailure $ fromIntegral status

-- | Check if the remote host has sent an EOF status for the selected stream. @True@ if the remote host has sent EOF, otherwise @False@.
isEof :: C.Channel -> IO (Either C.SshError Bool)
isEof c = do
  r <- C.channel_eof c
  return $ if r < 0
     then Left $ C.convertError r
     else Right $ intBool r

-- | Tell the remote host that no further data will be sent on the specified channel. Processes typically interpret this as a closed stdin descriptor.
sendEof :: C.Channel -> IO C.SshError
sendEof = fmap C.convertError . C.channel_send_eof

-- | Wait for the remote end to acknowledge an EOF request.
waitEof :: C.Channel -> IO C.SshError
waitEof = fmap C.convertError . C.channel_wait_eof

