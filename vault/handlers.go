package vault

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"

	"github.com/provideapp/ident/token"
	"github.com/provideapp/vault/common"
	provide "github.com/provideservices/provide-go/common"
)

// InstallAPI installs the handlers using the given gin Engine
func InstallAPI(r *gin.Engine) {
	r.GET("/api/v1/vaults", vaultsListHandler)
	r.POST("/api/v1/vaults", createVaultHandler)
	r.DELETE("/api/v1/vaults/:id", deleteVaultHandler)

	r.GET("/api/v1/vaults/:id/keys", vaultKeysListHandler)
	r.POST("/api/v1/vaults/:id/keys", createVaultKeyHandler)
	r.POST("/api/v1/vaults/:id/keys/:keyId/sign", vaultKeySignHandler)
	r.POST("/api/v1/vaults/:id/keys/:keyId/verify", vaultKeyVerifyHandler)
	r.POST("/api/v1/vaults/:id/keys/:keyId/encrypt", vaultKeyEncryptHandler)
	r.POST("/api/v1/vaults/:id/keys/:keyId/decrypt", vaultKeyDecryptHandler)
	r.DELETE("/api/v1/vaults/:id/keys/:keyId", deleteVaultKeyHandler)

	r.GET("/api/v1/vaults/:id/secrets", vaultSecretsListHandler)
	r.POST("api/v1/vaults/:id/secrets", createVaultSecretHandler)
	r.GET("api/v1/vaults/:id/secrets/:secretId", vaultSecretDetailsHandler)
	r.DELETE("api/v1/vaults/:id/secrets/:secretId", deleteVaultSecretHandler)

	r.POST("api/v1/unseal", vaultSealHandler)
	r.GET("api/v1/unseal", createUnsealerKeyHandler)
}

func createUnsealerKeyHandler(c *gin.Context) {
	_ = token.InContext(c)

	_, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	if common.UnsealerKey != nil {
		provide.RenderError("cannot generate unseal key from unsealed vault", 500, c)
		return
	}

	newUnsealerKey, err := CreateUnsealerKey()
	if err != nil {
		provide.RenderError(err.Error(), 500, c)
	}

	provide.Render(newUnsealerKey, 200, c)
	return
}

// vaultSealHandler enables locking and unlocking the master key for all vaults
func vaultSealHandler(c *gin.Context) {
	//q: what elements are required in the token to enable the locking/ unlocking of the vault?
	_ = token.InContext(c)

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	params := &SealUnsealRequest{}
	err = json.Unmarshal(buf, &params)
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	if params.UnsealerKey == nil {
		provide.RenderError("unsealer key material required", 422, c)
		return
	}

	// if params.SealKey != nil {
	// 	// we will lock the vault so it no longer operates
	// 	// this is the default starting state of the vault
	// 	// this doesn't make much sense (unless the locking is in itself
	// 	// an encryption action, but it will do for the moment)
	// 	// also better to wipe with random and then nil pointer
	// 	// NOTE - this makes no sense is right
	// 	// malicious sealing isn't something we want to deal with
	// 	randomJunk := common.RandomString(32)
	// 	*UnsealerKey = []byte(randomJunk)
	// 	UnsealerKey = nil
	// }

	if params.UnsealerKey != nil {
		// we will unlock the vault so it can perform key operations
		// first take the unlock key from the parameters and hex decode it to []byte

		// we will assume for the moment that the master key (the infinity key! - brand pending)
		// is an AES-256-GCM key's private key, hex encoded

		unsealerKey, err := hex.DecodeString(*params.UnsealerKey)
		if err != nil {
			provide.RenderError("error decoding unsealing key from hex", 500, c)
			return
		}

		// NOTE missing key to validate the key (compare it to the stored HASH of the key)
		err = SetUnsealerKey(&unsealerKey)
		if err != nil {
			vaultErr := fmt.Sprintf("error unsealing vault - %s", err.Error())
			provide.RenderError(vaultErr, 500, c)
			return
		}
		provide.Render("vault unsealed", 201, c)
	}
}

func vaultKeyEncryptHandler(c *gin.Context) {
	bearer := token.InContext(c)

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	params := &KeyEncryptDecryptRequestResponse{}
	err = json.Unmarshal(buf, &params)
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	if params.Data == nil {
		provide.RenderError("requires data to be encrypted", 422, c)
		return
	}

	// handle empty nonces
	nonce := []byte{}
	if params.Nonce != nil {
		nonce = []byte(*params.Nonce)
	} else {
		nonce = nil
	}

	var key = &Key{}
	key = GetVaultKey(c.Param("keyId"), c.Param("id"), bearer.ApplicationID, bearer.OrganizationID, bearer.UserID)

	if key.ID == uuid.Nil {
		provide.RenderError("key not found", 404, c)
		return
	}

	encryptedData, err := key.Encrypt([]byte(*params.Data), nonce)
	if err != nil {
		provide.RenderError(err.Error(), 500, c)
		return
	}

	encryptedDataHex := hex.EncodeToString(encryptedData)

	provide.Render(&KeyEncryptDecryptRequestResponse{
		Data: common.StringOrNil(string(encryptedDataHex)),
	}, 200, c)
}

func vaultKeyDecryptHandler(c *gin.Context) {
	bearer := token.InContext(c)

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	params := &KeyEncryptDecryptRequestResponse{}
	err = json.Unmarshal(buf, &params)
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	if params.Data == nil {
		provide.RenderError("requires data to be decrypted", 422, c)
		return
	}

	dataToDecrypt, err := hex.DecodeString(*params.Data)
	if err != nil {
		provide.RenderError("error decoding encrypted string to binary", 422, c)
		return
	}
	var key = &Key{}
	key = GetVaultKey(c.Param("keyId"), c.Param("id"), bearer.ApplicationID, bearer.OrganizationID, bearer.UserID)

	if key.ID == uuid.Nil {
		provide.RenderError("key not found", 404, c)
		return
	}

	decryptedData, err := key.Decrypt(dataToDecrypt)
	if err != nil {
		provide.RenderError(err.Error(), 500, c)
		return
	}

	decryptedDataString := string(decryptedData[:])

	provide.Render(&KeyEncryptDecryptRequestResponse{
		Data: common.StringOrNil(decryptedDataString),
	}, 200, c)
}

func vaultsListHandler(c *gin.Context) {
	bearer := token.InContext(c)

	var vaults []*Vault
	//vaults = GetVaults(bearer.ApplicationID, bearer.OrganizationID, bearer.UserID)

	var query *gorm.DB

	db := dbconf.DatabaseConnection()

	if bearer.ApplicationID != nil && *bearer.ApplicationID != uuid.Nil {
		query = db.Where("application_id = ?", bearer.ApplicationID)
	} else if bearer.OrganizationID != nil && *bearer.OrganizationID != uuid.Nil {
		query = db.Where("organization_id = ?", bearer.OrganizationID)
	} else if bearer.UserID != nil && *bearer.UserID != uuid.Nil {
		query = db.Where("user_id = ?", bearer.UserID)
	}

	provide.Paginate(c, query, &Vault{}).Find(&vaults)
	for _, vault := range vaults {
		vault.resolveMasterKey(db)
	}

	provide.Render(vaults, 200, c)
}

func createVaultHandler(c *gin.Context) {
	bearer := token.InContext(c)

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	vault := &Vault{}
	err = json.Unmarshal(buf, &vault)
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	//HACK: pull the vault information from the bearer token when creating a vault
	vault.ApplicationID = bearer.ApplicationID
	vault.OrganizationID = bearer.OrganizationID
	vault.UserID = bearer.UserID

	if bearer.ApplicationID != nil && vault.ApplicationID != nil && bearer.ApplicationID.String() != vault.ApplicationID.String() {
		err = errors.New("Failed to create vault; authorized application id did not match application_id provided in params")
		common.Log.Warningf(err.Error())
		provide.RenderError(err.Error(), 403, c)
		return
	}

	if bearer.OrganizationID != nil && vault.OrganizationID != nil && bearer.OrganizationID.String() != vault.OrganizationID.String() {
		err = errors.New("Failed to create vault; authorized organization id did not match organization_id provided in params")
		common.Log.Warningf(err.Error())
		provide.RenderError(err.Error(), 403, c)
		return
	}

	if bearer.UserID != nil && vault.UserID != nil && bearer.UserID.String() != vault.UserID.String() {
		err = errors.New("Failed to create vault; authorized user id did not match user_id provided in params")
		common.Log.Warningf(err.Error())
		provide.RenderError(err.Error(), 403, c)
		return
	}

	db := dbconf.DatabaseConnection()
	if !vault.Create(db) {
		err = fmt.Errorf("Failed to create vault; %s", *vault.Errors[0].Message)
		common.Log.Warningf(err.Error())
		provide.RenderError(err.Error(), 422, c)
		return
	}

	provide.Render(vault, 201, c)
	return
}

func deleteVaultHandler(c *gin.Context) {
	bearer := token.InContext(c)
	userID := bearer.UserID
	appID := bearer.ApplicationID
	orgID := bearer.OrganizationID
	if bearer == nil || ((userID == nil || *userID == uuid.Nil) && (appID == nil || *appID == uuid.Nil) && (orgID == nil || *orgID == uuid.Nil)) {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	db := dbconf.DatabaseConnection()
	tx := db.Begin()
	defer tx.RollbackUnlessCommitted()

	var vault = &Vault{}

	tx = tx.Where("id = ?", c.Param("id"))
	if bearer.UserID != nil {
		tx = tx.Where("user_id = ?", bearer.UserID)
	}
	if bearer.ApplicationID != nil {
		tx = tx.Where("application_id = ?", bearer.ApplicationID)
	}
	tx.Find(&vault)

	if vault.ID == uuid.Nil {
		provide.RenderError("vault not found", 404, c)
		return
	}
	if userID != nil && vault.UserID != nil && *userID != *vault.UserID {
		provide.RenderError("forbidden", 403, c)
		return
	}
	if appID != nil && vault.ApplicationID != nil && *appID != *vault.ApplicationID {
		provide.RenderError("forbidden", 403, c)
		return
	}
	if !vault.Delete(tx) {
		provide.RenderError("vault not deleted", 500, c)
		return
	}

	tx.Commit()
	provide.Render(nil, 204, c)
}

func vaultKeysListHandler(c *gin.Context) {
	bearer := token.InContext(c)

	var vault = &Vault{}

	db := dbconf.DatabaseConnection()
	var query *gorm.DB

	query = db.Where("id = ?", c.Param("id"))
	if bearer.ApplicationID != nil && *bearer.ApplicationID != uuid.Nil {
		query = query.Where("application_id = ?", bearer.ApplicationID)
	} else if bearer.OrganizationID != nil && *bearer.OrganizationID != uuid.Nil {
		query = query.Where("organization_id = ?", bearer.OrganizationID)
	} else if bearer.UserID != nil && *bearer.UserID != uuid.Nil {
		query = query.Where("user_id = ?", bearer.UserID)
	}
	query.Find(&vault)

	if vault.ID == uuid.Nil {
		provide.RenderError("vault not found", 404, c)
		return
	}

	// FIXME-- this is not covered by any test
	keysQuery := vault.ListKeysQuery(db)
	if c.Query("spec") != "" {
		keysQuery = keysQuery.Where("keys.spec = ?", c.Query("spec"))
	}
	if c.Query("type") != "" {
		keysQuery = keysQuery.Where("keys.type = ?", c.Query("type"))
	}
	keysQuery = keysQuery.Order("keys.created_at ASC")

	var keys []*Key
	provide.Paginate(c, keysQuery, &Key{}).Find(&keys)
	for _, key := range keys {
		key.Enrich()
	}
	provide.Render(keys, 200, c)
}

// Creates a key and stores it in vault
func createVaultKeyHandler(c *gin.Context) {
	bearer := token.InContext(c)

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	key := &Key{}
	err = json.Unmarshal(buf, &key)
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	if key.VaultID != nil {
		provide.RenderError("vault_id cannot be set explicitly", 422, c)
		return
	}

	if key.PublicKey != nil {
		provide.RenderError("importing key material is not currently supported; public_key should not be provided", 422, c)
		return
	}

	vault := &Vault{}
	vault = GetVault(c.Param("id"), bearer.ApplicationID, bearer.OrganizationID, bearer.UserID)

	if vault == nil || vault.ID == uuid.Nil {
		provide.RenderError("vault not found", 404, c)
		return
	}

	key.VaultID = &vault.ID
	key.vault = vault

	db := dbconf.DatabaseConnection()
	if key.createPersisted(db) {
		provide.Render(key, 201, c)
	} else {
		obj := map[string]interface{}{}
		obj["errors"] = key.Errors
		provide.Render(obj, 422, c)
	}
}

func deleteVaultKeyHandler(c *gin.Context) {
	bearer := token.InContext(c)

	var key = &Key{}
	key = GetVaultKey(c.Param("keyId"), c.Param("id"), bearer.ApplicationID, bearer.OrganizationID, bearer.UserID)

	if key.ID == uuid.Nil {
		provide.RenderError("key not found", 404, c)
		return
	}

	db := dbconf.DatabaseConnection()
	if !key.Delete(db) {
		provide.RenderError("key not deleted", 500, c)
		return
	}

	provide.Render(nil, 204, c)
}

func vaultKeySignHandler(c *gin.Context) {
	bearer := token.InContext(c)

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	params := &KeySignVerifyRequestResponse{}
	err = json.Unmarshal(buf, &params)
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	if params.Message == nil || params.Signature != nil || params.Verified != nil {
		provide.RenderError("only the message to be signed should be provided", 422, c)
		return
	}

	var key = &Key{}
	key = GetVaultKey(c.Param("keyId"), c.Param("id"), bearer.ApplicationID, bearer.OrganizationID, bearer.UserID)

	if key.ID == uuid.Nil {
		provide.RenderError("key not found", 404, c)
		return
	}

	signature, err := key.Sign([]byte(*params.Message), params.Options)
	if err != nil {
		provide.RenderError(err.Error(), 500, c)
		return
	}

	sighex := make([]byte, hex.EncodedLen(len(signature)))
	hex.Encode(sighex, signature)

	var address string
	if key.Address != nil {
		address = *key.Address
	}

	var path string
	if key.DerivationPath != nil {
		path = *key.DerivationPath
	}

	provide.Render(&KeySignVerifyRequestResponse{
		Signature:      common.StringOrNil(string(sighex)),
		Address:        common.StringOrNil(address),
		DerivationPath: common.StringOrNil(path),
	}, 201, c)
}

func vaultKeyVerifyHandler(c *gin.Context) {
	bearer := token.InContext(c)

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	params := &KeySignVerifyRequestResponse{}
	err = json.Unmarshal(buf, &params)
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	if params.Signature == nil || params.Message == nil || params.Verified != nil {
		provide.RenderError("only the message and signature to be verified should be provided", 422, c)
		return
	}

	var key = &Key{}
	key = GetVaultKey(c.Param("keyId"), c.Param("id"), bearer.ApplicationID, bearer.OrganizationID, bearer.UserID)

	if key.ID == uuid.Nil {
		provide.RenderError("key not found", 404, c)
		return
	}

	sig, err := hex.DecodeString(*params.Signature)
	if err != nil {
		msg := fmt.Sprintf("failed to decode signature from hex; %s", err.Error())
		provide.RenderError(msg, 422, c)
		return
	}

	err = key.Verify([]byte(*params.Message), sig, params.Options)
	verified := err == nil

	provide.Render(&KeySignVerifyRequestResponse{
		Verified: &verified,
	}, 201, c)
}

func vaultSecretsListHandler(c *gin.Context) {
	bearer := token.InContext(c)

	var vault = &Vault{}
	vault = GetVault(c.Param("id"), bearer.ApplicationID, bearer.OrganizationID, bearer.UserID)

	if vault.ID == uuid.Nil {
		provide.RenderError("vault not found", 404, c)
		return
	}

	db := dbconf.DatabaseConnection()

	// FIXME-- this is not covered by any test
	secretsQuery := vault.ListSecretsQuery(db)
	if c.Query("type") != "" {
		secretsQuery = secretsQuery.Where("secrets.type = ?", c.Query("type"))
	}
	secretsQuery = secretsQuery.Order("secrets.created_at ASC")

	var secrets []*Secret
	provide.Paginate(c, secretsQuery, &Secret{}).Find(&secrets)
	for _, secret := range secrets {
		secret.Value = nil
	}
	provide.Render(secrets, 200, c)
}

func vaultSecretDetailsHandler(c *gin.Context) {
	bearer := token.InContext(c)

	var secret = &Secret{}
	secret = GetVaultSecret(c.Param("secretId"), c.Param("id"), bearer.ApplicationID, bearer.OrganizationID, bearer.UserID)

	if secret.ID == uuid.Nil {
		provide.RenderError("secret not found", 404, c)
		return
	}

	decryptedSecret, err := secret.AsResponse()
	if err != nil {
		provide.RenderError(err.Error(), 500, c)
		return
	}

	provide.Render(&decryptedSecret, 200, c)
	return
}

func createVaultSecretHandler(c *gin.Context) {
	bearer := token.InContext(c)

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	secret := &Secret{}
	err = json.Unmarshal(buf, &secret)
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	if secret.VaultID != nil {
		provide.RenderError("vault_id cannot be set explicitly", 422, c)
		return
	}

	db := dbconf.DatabaseConnection() // FIXME-- pass this in to GetVault

	var vault = &Vault{}
	vault = GetVault(c.Param("id"), bearer.ApplicationID, bearer.OrganizationID, bearer.UserID)

	if vault == nil || vault.ID == uuid.Nil {
		provide.RenderError("vault not found", 404, c)
		return
	}

	secret.VaultID = &vault.ID
	secret.vault = vault

	if secret.Create(db) {
		provide.Render(secret, 201, c)
	} else {
		obj := map[string]interface{}{}
		obj["errors"] = secret.Errors
		provide.Render(obj, 422, c)
	}
}

func deleteVaultSecretHandler(c *gin.Context) {
	bearer := token.InContext(c)

	var secret = &Secret{}
	secret = GetVaultSecret(c.Param("secretId"), c.Param("id"), bearer.ApplicationID, bearer.OrganizationID, bearer.UserID)

	if secret.ID == uuid.Nil {
		provide.RenderError("secret not found", 404, c)
		return
	}
	common.Log.Debugf("secret id: %s", secret.ID)

	db := dbconf.DatabaseConnection()
	if !secret.Delete(db) {
		provide.RenderError("error deleting secret", 500, c)
		return
	}

	provide.Render("secret deleted", 204, c)
	return
}
