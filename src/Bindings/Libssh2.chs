#include <libssh2.h>
{#context lib = "ssh2" prefix = "libssh2" #}
module Bindings.Libssh2 where
import Data.Coerce
import Data.Int
import Foreign.C
import Foreign.Marshal.Alloc
import Foreign.Storable
import Foreign.ForeignPtr
import Foreign.Ptr
import System.Posix.Files
import Unsafe.Coerce

-- $ Global setup and teardown
newtype InitFlags = InitFlags CInt

normal :: InitFlags
normal = InitFlags 0

noCrypto :: InitFlags
noCrypto = InitFlags {#const LIBSSH2_INIT_NO_CRYPTO #}

type StatusCode = CInt

{#enum define SshError
  { LIBSSH2_ERROR_NONE         as NoError
  , LIBSSH2_ERROR_BANNER_RECV  as BannerRecv
  , LIBSSH2_ERROR_BANNER_SEND  as BannerSend
  , LIBSSH2_ERROR_INVALID_MAC  as InvalidMac
  , LIBSSH2_ERROR_KEX_FAILURE  as KexFailure
  , LIBSSH2_ERROR_ALLOC        as Alloc
  , LIBSSH2_ERROR_SOCKET_SEND  as SocketSend
  , LIBSSH2_ERROR_KEY_EXCHANGE_FAILURE as KeyExchangeFailure
  , LIBSSH2_ERROR_TIMEOUT      as Timeout
  , LIBSSH2_ERROR_HOSTKEY_INIT as HostkeyInit
  , LIBSSH2_ERROR_HOSTKEY_SIGN as HostkeySign
  , LIBSSH2_ERROR_DECRYPT      as Decrypt
  , LIBSSH2_ERROR_SOCKET_DISCONNECT as SocketDisconnect
  , LIBSSH2_ERROR_PROTO        as Proto
  , LIBSSH2_ERROR_PASSWORD_EXPIRED as PasswordExpired
  , LIBSSH2_ERROR_FILE         as File
  , LIBSSH2_ERROR_METHOD_NONE  as MethodNone
  , LIBSSH2_ERROR_AUTHENTICATION_FAILED as AuthenticationFailed
  , LIBSSH2_ERROR_PUBLICKEY_UNRECOGNIZED as PublicKeyUnrecognized
  , LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED as PublicKeyUnverified
  , LIBSSH2_ERROR_CHANNEL_OUTOFORDER as ChannelOutOfOrder
  , LIBSSH2_ERROR_CHANNEL_FAILURE as ChannelFailure
  , LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED as ChannelRequestDenied
  , LIBSSH2_ERROR_CHANNEL_UNKNOWN as ChannelUnknown
  , LIBSSH2_ERROR_CHANNEL_WINDOW_EXCEEDED as ChannelWindowExceeded
  , LIBSSH2_ERROR_CHANNEL_PACKET_EXCEEDED as ChannelPacketExceeded
  , LIBSSH2_ERROR_CHANNEL_CLOSED as ChannelClosed
  , LIBSSH2_ERROR_CHANNEL_EOF_SENT as EofSent
  , LIBSSH2_ERROR_SCP_PROTOCOL as ScpProtocol
  , LIBSSH2_ERROR_ZLIB as Zlib
  , LIBSSH2_ERROR_SOCKET_TIMEOUT as SocketTimeout
  , LIBSSH2_ERROR_SFTP_PROTOCOL as SftpProtocol
  , LIBSSH2_ERROR_REQUEST_DENIED as RequestDenied
  , LIBSSH2_ERROR_METHOD_NOT_SUPPORTED as MethodNotSupported
  , LIBSSH2_ERROR_INVAL as Inval
  , LIBSSH2_ERROR_INVALID_POLL_TYPE as InvalidPollType
  , LIBSSH2_ERROR_PUBLICKEY_PROTOCOL as PublicKeyProtocol
  , LIBSSH2_ERROR_EAGAIN as WouldBlock
  , LIBSSH2_ERROR_BUFFER_TOO_SMALL as BufferTooSmall
  , LIBSSH2_ERROR_BAD_USE as BadUse
  , LIBSSH2_ERROR_COMPRESS as Compress
  , LIBSSH2_ERROR_OUT_OF_BOUNDARY as OutOfBoundary
  , LIBSSH2_ERROR_AGENT_PROTOCOL as AgentProtocol
  , LIBSSH2_ERROR_SOCKET_RECV as SocketRecv
  , LIBSSH2_ERROR_ENCRYPT as Encrypt
  , LIBSSH2_ERROR_BAD_SOCKET as BadSocket
  , LIBSSH2_ERROR_KNOWN_HOSTS as KnownHosts
  } deriving (Show, Eq, Ord) #}

convertError :: CInt -> SshError
convertError = toEnum . fromIntegral

{#fun init { coerce `InitFlags' } -> `CInt' #}
{#fun exit {} -> `()' #}
{#fun free { coerce `Session'
           , castPtr `Ptr a'
           } -> `()' #}
{#fun version { `CInt' } -> `String' #}

-- $ Session API

newtype Session = Session (Ptr ())
  deriving (Show)

type AllocFunc = CULong -> Ptr (Ptr ()) -> IO (Ptr ())
type ReallocFunc = Ptr () -> CULong -> Ptr (Ptr ()) -> IO (Ptr ())
type FreeFunc = Ptr () -> Ptr (Ptr ()) -> IO ()

newtype MethodType = MethodType CInt

methodKex :: MethodType
methodKex = MethodType {#const LIBSSH2_METHOD_KEX #}

methodHostkey :: MethodType
methodHostkey = MethodType {#const LIBSSH2_METHOD_HOSTKEY #}

methodCryptCS :: MethodType
methodCryptCS = MethodType {#const LIBSSH2_METHOD_CRYPT_CS #}

methodCryptSC :: MethodType
methodCryptSC = MethodType {#const LIBSSH2_METHOD_CRYPT_SC #}

methodMacCS :: MethodType
methodMacCS = MethodType {#const LIBSSH2_METHOD_MAC_CS #}

methodMacSC :: MethodType
methodMacSC = MethodType {#const LIBSSH2_METHOD_MAC_SC #}

methodCompCS :: MethodType
methodCompCS = MethodType {#const LIBSSH2_METHOD_COMP_CS #}

methodCompSC :: MethodType
methodCompSC = MethodType {#const LIBSSH2_METHOD_COMP_SC #}

methodLangCS :: MethodType
methodLangCS = MethodType {#const LIBSSH2_METHOD_LANG_CS #}

methodLangSC :: MethodType
methodLangSC = MethodType {#const LIBSSH2_METHOD_LANG_SC #}

{#fun session_supported_algs
  { coerce `Session'
  , coerce `MethodType'
  , alloca- `Ptr CString' peek*
  } -> `CInt' #}

{#fun session_init_ex { id `FunPtr AllocFunc'
                      , id `FunPtr FreeFunc'
                      , id `FunPtr ReallocFunc'
                      , `Ptr ()'
                      } -> `Session' coerce #}

{#fun session_abstract { coerce `Session'
                       } -> `Ptr (Ptr a)' castPtr #}


newtype CallbackType sig = CallbackType CInt

type Abstract = Ptr (Ptr ())

ignoreCallback :: CallbackType (Session -> CString -> CInt -> Abstract -> IO ())
ignoreCallback = CallbackType {#const LIBSSH2_CALLBACK_IGNORE #}

debugCallback :: CallbackType (Session -> CInt -> CString -> CInt -> CString -> CInt -> Abstract -> IO ())
debugCallback = CallbackType {#const LIBSSH2_CALLBACK_DEBUG #}

disconnectCallback :: CallbackType (Session -> CInt -> CString -> CInt -> CString -> CInt -> Abstract -> IO ())
disconnectCallback = CallbackType {#const LIBSSH2_CALLBACK_DISCONNECT #}

macErrorCallback :: CallbackType (Session -> CString -> CInt -> Abstract -> IO CInt)
macErrorCallback = CallbackType {#const LIBSSH2_CALLBACK_MACERROR #}

x11Callback :: CallbackType (Session -> Channel -> CString -> CInt -> Abstract -> IO ())
x11Callback = CallbackType {#const LIBSSH2_CALLBACK_X11 #}

-- TODO, is CSize right? Header uses ssize_t
sendCallback :: CallbackType (Socket -> Ptr () -> CSize -> CInt -> Abstract -> IO CSize)
sendCallback = CallbackType {#const LIBSSH2_CALLBACK_SEND #}

recvCallback :: CallbackType (Socket -> Ptr () -> CSize -> CInt -> Abstract -> IO CSize)
recvCallback = CallbackType {#const LIBSSH2_CALLBACK_RECV #}

{#fun session_callback_set
  { coerce `Session'
  , coerce `CallbackType sig'
  , castFunPtrToPtr `FunPtr sig'
  } -> `FunPtr sig' castPtrToFunPtr #}

{#fun session_banner_set
  { coerce `Session'
  , `CString'
  } -> `CInt' #}

{#fun session_startup
  { coerce `Session'
  , coerce `Socket'
  } -> `CInt' #}

{#fun session_handshake
  { coerce `Session'
  , coerce `Socket'
  } -> `CInt' #}

newtype DisconnectReason = DisconnectReason CInt

host_not_allowed_to_connect :: DisconnectReason
host_not_allowed_to_connect = DisconnectReason {#const SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT #}
protocol_error :: DisconnectReason
protocol_error = DisconnectReason {#const SSH_DISCONNECT_PROTOCOL_ERROR #}
key_exchange_failed :: DisconnectReason
key_exchange_failed = DisconnectReason {#const SSH_DISCONNECT_KEY_EXCHANGE_FAILED #}
reserved :: DisconnectReason
reserved = DisconnectReason {#const SSH_DISCONNECT_RESERVED #}
mac_error :: DisconnectReason
mac_error = DisconnectReason {#const SSH_DISCONNECT_MAC_ERROR #}
compression_error :: DisconnectReason
compression_error = DisconnectReason {#const SSH_DISCONNECT_COMPRESSION_ERROR #}
service_not_available :: DisconnectReason
service_not_available = DisconnectReason {#const SSH_DISCONNECT_SERVICE_NOT_AVAILABLE #}
protocol_version_not_supported :: DisconnectReason
protocol_version_not_supported = DisconnectReason {#const SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED #}
host_key_not_verifiable :: DisconnectReason
host_key_not_verifiable = DisconnectReason {#const SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE #}
connection_lost :: DisconnectReason
connection_lost = DisconnectReason {#const SSH_DISCONNECT_CONNECTION_LOST #}
by_application :: DisconnectReason
by_application = DisconnectReason {#const SSH_DISCONNECT_BY_APPLICATION #}
too_many_connections :: DisconnectReason
too_many_connections = DisconnectReason {#const SSH_DISCONNECT_TOO_MANY_CONNECTIONS #}
auth_cancelled_by_user :: DisconnectReason
auth_cancelled_by_user = DisconnectReason {#const SSH_DISCONNECT_AUTH_CANCELLED_BY_USER #}
no_more_auth_methods_available :: DisconnectReason
no_more_auth_methods_available = DisconnectReason {#const SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE #}
illegal_user_name :: DisconnectReason
illegal_user_name = DisconnectReason {#const SSH_DISCONNECT_ILLEGAL_USER_NAME #}

{#fun session_disconnect_ex
  { coerce `Session'
  , coerce `DisconnectReason'
  , `CString'
  , `CString'
  } -> `CInt' #}

{#fun session_free
  { coerce `Session'
  } -> `CInt' #}

foreign import ccall "cbits.c &libssh2_session_free_discard_result"
   session_free_wrapper :: FunPtr (Session -> IO ())

{#fun hostkey_hash
  { coerce `Session'
  , `CInt' -- TODO hash type
  } -> `CString' #}

{#fun session_hostkey
  { coerce `Session'
  , alloca- `CULong' peek*
  , alloca- `CInt' peek* -- TODO type
  } -> `CString' #}

{#fun session_method_pref
  { coerce `Session'
  , `CInt' -- TODO type
  , `CString'
  } -> `CInt' #}

{#fun session_methods
  { coerce `Session'
  , `CInt' -- TODO type
  } -> `CString' #}

{#fun session_last_error
  { coerce `Session'
  , alloca- `CString' peek*
  , alloca- `CInt' peek*
  , `CInt'
  } -> `CInt' #}

{#fun session_last_errno
  { coerce `Session'
  } -> `CInt' #}

{#fun session_set_last_error
  { coerce `Session'
  , `CInt'
  , `CString'
  } -> `CInt' #}

data BlockDirections = Inbound
                     | Outbound
                     | Bidirectional
                     deriving (Show, Eq)

blockInbound :: Int
blockInbound = {#const LIBSSH2_SESSION_BLOCK_INBOUND #}

blockOutbound :: Int
blockOutbound = {#const LIBSSH2_SESSION_BLOCK_OUTBOUND #}

{#fun session_block_directions
  { coerce `Session'
  } -> `CInt' #}

{#fun session_flag
  { coerce `Session'
  , `CInt' -- TODO an actual type
  , `CInt'
  } -> `CInt' #}

{#fun session_banner_get
  { coerce `Session'
  } -> `CString' #}

-- $ Userauth

{#fun userauth_list
  { coerce `Session'
  , `CString'
  , `CUInt'
  } -> `CString' #}

{#fun userauth_authenticated
  { coerce `Session'
  } -> `CInt' #}

type PasswordChange = Session -> Ptr CString -> Ptr CInt -> Abstract -> IO ()

{#fun userauth_password_ex
  { coerce `Session'
  , `CString'
  , `CUInt'
  , `CString'
  , `CUInt'
  , castFunPtr `FunPtr PasswordChange'
  } -> `CInt' #}

{#fun userauth_publickey_fromfile_ex
  { coerce `Session'
  , `CString'
  , `CUInt'
  , `CString'
  , `CString'
  , `CString'
  } -> `CInt' #}

type Sign = Session -> Ptr (Ptr CUChar) -> Ptr CULong -> Ptr CUChar -> CULong -> Abstract -> IO CInt

{#fun userauth_publickey
  { coerce `Session'
  , `CString'
  , id `Ptr CUChar'
  , `CULong'
  , castFunPtr `FunPtr Sign'
  , id `Abstract'
  } -> `CInt' #}

{#fun userauth_hostbased_fromfile_ex
  { coerce `Session'
  , `CString'
  , `CUInt'
  , `CString'
  , `CString'
  , `CString'
  , `CString'
  , `CUInt'
  , `CString'
  , `CUInt'
  } -> `CInt' #}

{#fun userauth_publickey_frommemory
  { coerce `Session'
  , `CString'
  , `CULong'
  , `CString'
  , `CULong'
  , `CString'
  , `CULong'
  , `CString'
  } -> `CInt' #}

type KeyboardInterrupt
  =  CString
  -> CInt
  -> CString
  -> CInt
  -> CInt
  -> Ptr KeyboardInterruptPrompt
  -> Ptr KeyboardInterruptResponse
  -> Abstract
  -> IO ()

data KeyboardInterruptPrompt = KeyboardInterruptPrompt
                               { keyboardInterruptPromptText   :: CString
                               , keyboardInterruptPromptLength :: CUInt
                               , keyboardInterruptPromptEcho   :: CUChar
                               }

data KeyboardInterruptResponse = KeyboardInterruptResponse
                                 { keyboardInterruptResponseText   :: CString
                                 , keyboardInterruptResponseLength :: CUInt
                                 }

{#fun userauth_keyboard_interactive_ex
  { coerce `Session'
  , `CString'
  , `CUInt'
  , castFunPtr `FunPtr KeyboardInterrupt'
  } -> `CInt' #}

-- $ Channel
newtype Channel = Channel (Ptr ())
  deriving (Show)
newtype Listener = Listner (Ptr ())

channel_window_default :: Num a => a
channel_window_default = {#const LIBSSH2_CHANNEL_WINDOW_DEFAULT #}

channel_packet_default :: Num a => a
channel_packet_default = {#const LIBSSH2_CHANNEL_PACKET_DEFAULT #}

{#fun channel_open_ex
  { coerce `Session'
  , `CString'
  , `CUInt'
  , `CUInt'
  , `CUInt'
  , `CString'
  , `CUInt'
  } -> `Channel' coerce #}

{#fun channel_direct_tcpip_ex
  { coerce `Session'
  , `CString'
  , `CInt'
  , `CString'
  , `CInt'
  } -> `Channel' coerce #}

{#fun channel_forward_listen_ex
  { coerce `Session'
  , `CString'
  , `CInt'
  , alloca- `CInt' peek*
  , `CInt'
  } -> `Listener' coerce #}

{#fun channel_forward_cancel
  { coerce `Listener'
  } -> `CInt' #}

{#fun channel_forward_accept
  { coerce `Listener'
  } -> `Channel' coerce #}

{#fun channel_setenv_ex
  { coerce `Channel'
  , `CString'
  , `CUInt'
  , `CString'
  , `CUInt'
  } -> `CInt' #}

{#fun channel_request_pty_ex
  { coerce `Channel'
  , `CString'
  , `CUInt'
  , `CString'
  , `CUInt'
  , `CInt'
  , `CInt'
  , `CInt'
  , `CInt'
  } -> `CInt' #}

{#fun channel_request_pty_size_ex
  { coerce `Channel'
  , `CInt'
  , `CInt'
  , `CInt'
  , `CInt'
  } -> `CInt' #}

{#fun channel_x11_req_ex
  { coerce `Channel'
  , `CInt'
  , `CString'
  , `CString'
  , `CInt'
  } -> `CInt' #}

{#fun channel_process_startup
  { coerce `Channel'
  , `CString'
  , `CUInt'
  , `CString'
  , `CUInt'
  } -> `CInt' #}

{#fun channel_read_ex
  { coerce `Channel'
  , `CInt'
  , `CString'
  , `CULong'
  } -> `CLong' #}

{#fun channel_window_read_ex
  { coerce `Channel'
  , id `Ptr CULong'
  , id `Ptr CULong'
  } -> `CULong' #}

{#fun channel_receive_window_adjust2
  { coerce `Channel'
  , `CULong'
  , id `CUChar'
  , alloca- `CUInt' peek*
  } -> `CInt' #}

{#fun channel_write_ex
  { coerce `Channel'
  , `CInt'
  , `CString'
  , `CULong'
  } -> `CLong' #}

{#fun channel_window_write_ex
  { coerce `Channel'
  , id `Ptr CULong'
  } -> `CULong' #}

{#fun session_set_blocking
  { coerce `Session'
  , `CInt'
  } -> `()' #}

{#fun session_get_blocking
  { coerce `Session'
  } -> `CInt' #}

{#fun channel_set_blocking
  { coerce `Channel'
  , `CInt'
  } -> `()' #}

{#fun session_set_timeout
  { coerce `Session'
  , `CLong'
  } -> `()' #}

{#fun session_get_timeout
  { coerce `Session'
  } -> `CLong' #}

{#fun channel_handle_extended_data2
  { coerce `Channel'
  , `CInt'
  } -> `CInt' #}

{#fun channel_flush_ex
  { coerce `Channel'
  , `CInt'
  } -> `CInt' #}

{#fun channel_get_exit_status
  { coerce `Channel'
  } -> `CInt' #}

{#fun channel_get_exit_signal
  { coerce `Channel'
  , alloca- `CString' peek*
  , alloca- `CULong' peek*
  , alloca- `CString' peek*
  , alloca- `CULong' peek*
  , alloca- `CString' peek*
  , alloca- `CULong' peek*
  } -> `CInt' #}

{#fun channel_send_eof
  { coerce `Channel'
  } -> `CInt' #}

{#fun channel_eof
  { coerce `Channel'
  } -> `CInt' #}

{#fun channel_wait_eof
  { coerce `Channel'
  } -> `CInt' #}

{#fun channel_close
  { coerce `Channel'
  } -> `CInt' #}

{#fun channel_wait_closed
  { coerce `Channel'
  } -> `CInt' #}

{#fun channel_free
  { coerce `Channel'
  } -> `CInt' #}

foreign import ccall "cbits.c &libssh2_channel_free_discard_result"
   channel_free_wrapper :: FunPtr (Channel -> IO ())


unsafeMallocFileStatus :: IO FileStatus
unsafeMallocFileStatus = do
  fp <- mallocForeignPtrBytes {#sizeof stat #}
  return $ unsafeCoerce fp

{#fun scp_recv2
  { coerce `Session'
  , `CString'
  , `Ptr ()' -- Must be a filestatus struct, I think...
  } -> `Channel' coerce #}

{#fun scp_send_ex
  { coerce `Session'
  , `CString'
  , `CInt'
  , `CULong'
  , `CLong'
  , `CLong'
  } -> `Channel' coerce #}

{#fun scp_send64
  { coerce `Session'
  , `CString'
  , `CInt'
  , `Int64'
  , `CLong'
  , `CLong'
  } -> `Channel' coerce #}

{#fun base64_decode
  { coerce `Session'
  , alloca- `CString' peek*
  , alloca- `CUInt' peek*
  , `CString'
  , `CUInt' } -> `CInt' #}

-- $ Socket
newtype Socket = Socket CInt
