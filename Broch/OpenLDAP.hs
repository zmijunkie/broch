{-# LANGUAGE OverloadedStrings, FlexibleInstances, RecordWildCards #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

-- https://stackoverflow.com/questions/13831041/haskell-ldap-authentication

module Broch.OpenLdap
    ( 
    , openldapBackend
    , passwordAuthenticate
    )
where

import           Control.Monad (void)
import           Control.Monad.IO.Class
import           Crypto.KDF.BCrypt (hashPassword, validatePassword)
import           Data.Aeson
import           Data.ByteString (ByteString)
import           Data.ByteString.Lazy (toStrict)
import           Data.Pool
import           Data.Text (Text)
import qualified Data.Text as T
import           Data.Text.Encoding (decodeUtf8, encodeUtf8)
import           Data.Time.Calendar
import           Data.Time.Clock.POSIX
import           Data.Typeable (Typeable)
-- import           Database.SQLite.Simple
-- import           Database.SQLite.Simple.FromField
-- import           Database.SQLite.Simple.FromRow
-- import           Database.SQLite.Simple.Internal
-- import           Database.SQLite.Simple.ToField
import           Jose.Jwa (JwsAlg(..))
import           Jose.Jwk (Jwk)
import           Jose.Jwt (IntDate (..))

import           Broch.Model as M
-- import           Broch.Test.Data (testClients)
import           Broch.URI
import           Broch.Server.Config


openldapBackend :: (MonadIO m, M.Subject s) => Pool Connection -> Config m s -> Config m s
openldapBackend pool config = config
    { getClient = \cid -> liftIO $ withResource pool (`loadClient` cid)
    , createClient = \clnt -> liftIO $ withResource pool (`insertClient` clnt)
    , createAuthorization = \code usr clnt now scp n uri -> liftIO $ withResource pool (\c -> insertAuthorization c code usr clnt now scp n uri)
    , getAuthorization = \code -> liftIO $ withResource pool (`loadAndDeleteAuthorization` code)
    , createApproval = \a -> liftIO $ withResource pool (`insertApproval` a)
    , getApproval = \uid clnt now -> liftIO $ withResource pool (\conn -> loadApproval conn uid (clientId clnt) now)
    , getUserInfo = \uid clnt -> liftIO $ withResource pool (\conn -> loadUserInfo conn uid clnt)
    }

-- postgreSQLBackend :: (MonadIO m, M.Subject s) => Pool Connection -> Config m s -> Config m s
-- postgreSQLBackend pool config = config
--     { getClient = liftIO . loadClient pool
--     , createClient = liftIO . insertClient pool
--     , createAuthorization = \code usr clnt now scp n uri -> liftIO (insertAuthorization pool code usr clnt now scp n uri)
--     , getAuthorization = liftIO . loadAndDeleteAuthorization pool
--     , createApproval = liftIO . insertApproval pool
--     , getApproval = \uid clnt now -> liftIO $ withResource pool (\conn -> loadApproval conn uid (clientId clnt) now)
--     , getUserInfo = \uid clnt -> liftIO (loadUserInfo pool uid clnt)
--     }



-- instance FromField ClientAuthMethod where
--     fromField f@(Field (SQLText v) _) =
--         -- TODO: Check type info
--         case lookupClientAuth v of
--             Nothing -> returnError ConversionFailed f "Unknown client auth"
--             (Just cam) -> return cam
--     fromField f = returnError Incompatible f "Expected a text field for client auth"

-- instance FromField [GrantType] where
--     fromField (Field SQLNull _) = return []
--     fromField f@(Field (SQLText v) _) = case mapM lookupGrantType (T.splitOn "," v) of
--         Nothing -> returnError ConversionFailed f "Unknown grant type"
--         Just gs -> return gs
--     fromField f = returnError Incompatible f "Expected a text field for grant types"

-- instance ToField [GrantType] where
--     toField = SQLText . T.intercalate  "," . map grantTypeName

-- instance FromField [Scope] where
--     fromField (Field SQLNull _) = return []
--     fromField (Field (SQLText v) _) = mapM (return . scopeFromName) (T.splitOn "," v)
--     fromField f = returnError Incompatible f "Expected a text field for scopes"

-- instance ToField [Scope] where
--     toField [] = SQLNull
--     toField scps = SQLText . T.intercalate "," $ map scopeName scps

-- instance FromField JwsAlg where
--     fromField f@(Field (SQLText v) _) =
--         case lookupJwsAlg v of
--             Nothing -> returnError ConversionFailed f "Unknown JWS algorithm"
--             (Just a) -> return a
--     fromField f = returnError Incompatible f "Expected a text field for JWS algorithms"

-- instance FromField [URI] where
--     fromField (Field SQLNull _) = return []
--     fromField f@(Field (SQLText v) _) = case mapM parseURI (T.splitOn "," v) of
--         Left _ -> returnError ConversionFailed f "Could not parse stored URI"
--         (Right u) -> return u
--     fromField f = returnError Incompatible f "Expected a text field for URIs"

-- instance ToField [URI] where
--     toField = SQLText . T.intercalate "," . map (decodeUtf8 . renderURI)

-- instance FromField URI where
--     fromField f@(Field (SQLText v) _) = case parseURI v of
--         Left _ -> returnError ConversionFailed f "Could not parse stored URI"
--         (Right u) -> return u
--     fromField f = returnError Incompatible f "Expected a text field for URI"

-- instance ToField URI where
--     toField = SQLText . decodeUtf8 . renderURI

-- instance FromField [Jwk] where
--     fromField = fromJSONField

-- instance FromField AlgPrefs where
--     fromField = fromJSONField

-- fromJSONField :: (FromJSON a, Typeable a) => FieldParser a
-- fromJSONField f = case f of
--     (Field SQLNull _) -> returnError UnexpectedNull f ""
--     (Field (SQLText v) _) -> case eitherDecodeStrict (encodeUtf8 v) of
--         Left e  -> returnError ConversionFailed f $ "Could not decode JSON field: " ++ e
--         Right x -> return x
--     _ -> returnError Incompatible f "Expected a text field to convert to JSON"

-- toJSONField :: ToJSON a => Maybe a -> SQLData
-- toJSONField = maybe SQLNull (SQLText . decodeUtf8 . toStrict . encode)

-- instance FromRow Client where
--     fromRow = Client <$> field <*> field <*> field <*> field <*> field <*> field <*> field <*> field <*> field <*> field <*> field <*> field <*> field <*> field <*> field <*> field

-- instance FromRow UserInfo where
--     fromRow = UserInfo <$> field <*> field <*> field <*> field <*> field <*> field <*> field <*> field <*> field <*> field <*> field <*> field <*> field <*> parseBirthDate <*> field <*> field <*> field <*> field <*> parseAddress <*> parseIntDate

-- parseAddress :: RowParser (Maybe AddressClaims)
-- parseAddress = do
--     r <- fromRow
--     return $ case r of
--         (Nothing, Nothing, Nothing, Nothing, Nothing, Nothing) -> Nothing
--         (fmt, street, loc, reg, post, ctry) -> Just (AddressClaims fmt street loc reg post ctry)

-- parseBirthDate :: RowParser (Maybe Text)
-- parseBirthDate = do
--     day <- field :: RowParser (Maybe Day)
--     return $ fmap (T.pack . showGregorian) day

-- parseIntDate :: RowParser (Maybe IntDate)
-- parseIntDate = do
--     utc <- field
--     return $ fmap (IntDate . utcTimeToPOSIXSeconds) utc

-- insertAuthorization :: M.Subject s
--     => Connection
--     -> Text
--     -> s
--     -> M.Client
--     -> POSIXTime
--     -> [M.Scope]
--     -> Maybe Text
--     -> Maybe URI
--     -> IO ()
-- insertAuthorization conn code user client now scope nonce mURI =
--     void $ execute conn "insert into authz_code (code, uid, client_id, issued_at, scope, nonce, uri, auth_time) values (?,?,?,?,?,?,?,?)" (code, M.subjectId user, M.clientId client, posixSecondsToUTCTime now, scope, nonce, mURI, posixSecondsToUTCTime (M.authTime user))

-- loadAndDeleteAuthorization :: Connection -> Text -> IO (Maybe Authorization)
-- loadAndDeleteAuthorization conn code = do
--     as <- query conn "SELECT uid, client_id, issued_at, scope, nonce, uri, auth_time FROM authz_code WHERE code = ?" [code]
--     execute conn "DELETE FROM authz_code WHERE code = ?" [code]
--     return $ case as of
--         [(uid, cid, iat, scp, nonce, uri, autht)] -> Just (Authorization uid cid (IntDate (utcTimeToPOSIXSeconds iat)) scp nonce uri (utcTimeToPOSIXSeconds autht))
--         _ -> Nothing

-- insertApproval :: Connection -> M.Approval -> IO ()
-- insertApproval conn (M.Approval uid cid scope denied (IntDate expires)) =
--     void $ execute conn "INSERT OR REPLACE INTO authz_approval (uid, client_id, scope, denied_scope, expires_at) VALUES (?,?,?,?,?)"
--         (uid, cid, scope, denied, posixSecondsToUTCTime expires)

-- loadApproval :: Connection -> SubjectId -> ClientId -> POSIXTime -> IO (Maybe Approval)
-- loadApproval conn uid cid now = do
--     as <- query conn "SELECT scope, denied_scope, expires_at FROM authz_approval WHERE uid = ? AND client_id = ? AND expires_at > ? ORDER BY expires_at DESC" (uid, cid, posixSecondsToUTCTime now)
--     return $ case filter notExpired as of
--         [(scope, denied, expires)] -> Just (Approval uid cid scope denied (IntDate (utcTimeToPOSIXSeconds expires)))
--         _ -> Nothing
--   where
--     notExpired (_, _, t) = t > posixSecondsToUTCTime now

-- jwsAlgName :: JwsAlg -> Text
-- jwsAlgName a = case a of
--     None  -> "none"
--     HS256 -> "HS256"
--     HS384 -> "HS384"
--     HS512 -> "HS512"
--     RS256 -> "RS256"
--     RS384 -> "RS384"
--     RS512 -> "RS512"
--     ES256 -> "ES256"
--     ES384 -> "ES384"
--     ES512 -> "ES512"

-- lookupJwsAlg :: Text -> Maybe JwsAlg
-- lookupJwsAlg nm = case nm of
--     "none"  -> Just None
--     "HS256" -> Just HS256
--     "HS384" -> Just HS384
--     "HS512" -> Just HS512
--     "RS256" -> Just RS256
--     "RS384" -> Just RS384
--     "RS512" -> Just RS512
--     "ES256" -> Just ES256
--     "ES384" -> Just ES384
--     "ES512" -> Just ES512
--     _       -> Nothing

-- insertClient :: Connection -> Client -> IO ()
-- insertClient conn Client{..} =
--     void $ execute conn "INSERT INTO oauth2_client (id, secret, redirect_uri, allowed_scope, authorized_grant_types, access_token_validity, refresh_token_validity, auth_method, auth_alg, keys_uri, keys, id_token_algs, user_info_algs, request_obj_algs, sector_identifier, auto_approve) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)" ((clientId, clientSecret, redirectURIs, allowedScope, authorizedGrantTypes, accessTokenValidity, refreshTokenValidity, clientAuthMethodName tokenEndpointAuthMethod, fmap jwsAlgName tokenEndpointAuthAlg, clientKeysUri) :. (toJSONField clientKeys, toJSONField idTokenAlgs, toJSONField userInfoAlgs, toJSONField requestObjAlgs, sectorIdentifier, autoapprove))

-- loadClient :: Connection -> ClientId -> IO (Maybe Client)
-- loadClient conn cid = do
--     cs <- query conn "SELECT id, secret, authorized_grant_types, redirect_uri, access_token_validity, refresh_token_validity, allowed_scope, auto_approve, auth_method, auth_alg, keys_uri, keys, id_token_algs, user_info_algs, request_obj_algs, sector_identifier FROM oauth2_client WHERE id = ?"  [cid]
--     return $ case cs of
--         [c] -> Just c
--         _   -> Nothing

-- loadUserInfo :: Connection -> LoadUserInfo IO
-- loadUserInfo conn uid _ = do
--     us <- query conn "SELECT * FROM user_info WHERE id=?" [uid]
--     return $ case us of
--         [u] -> Just u
--         _   -> Nothing

-- passwordAuthenticate :: Connection -> (ByteString -> ByteString -> Bool) -> Text -> ByteString -> IO (Maybe SubjectId)
-- passwordAuthenticate conn validatePwd username password = do
--     us <- query conn "SELECT id, password FROM op_user WHERE username = ?" [username]
--     return $ case us of
--        [(uid, encodedPwd)] -> if validatePwd password (encodeUtf8 encodedPwd)
--                                   then Just uid
--                                   else Nothing
--        _ -> Nothing
