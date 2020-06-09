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
	provide "github.com/provideservices/provide-go"
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

	r.GET("/api/v1/vaults/:id/secrets", vaultSecretsListHandler)
}

func vaultsListHandler(c *gin.Context) {
	bearer := token.InContext(c)

	var vaults []*Vault
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

	var keys []*Key
	provide.Paginate(c, vault.ListKeysQuery(db), &Key{}).Find(&keys)
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

	if vault == nil || vault.ID == uuid.Nil {
		provide.RenderError("vault not found", 404, c)
		return
	}

	key.VaultID = &vault.ID

	switch *key.Spec {
	case keySpecChaCha20:
		provide.RenderError("implementation in progress", 422, c)
	case keySpecAES256GCM:
		provide.RenderError("implementation in progress", 422, c)
	case keySpecECCSecp256k1:
		err = key.CreateSecp256k1Keypair()
		if err != nil {
			common.Log.Warningf("failed to create secp256k1 keypair; %s", err.Error())
			return
		}
	case keySpecECCEd25519:
		err = key.CreateEd25519Keypair()
		if err != nil {
			common.Log.Warningf("failed to create Ed22519 keypair; %s", err.Error())
			return
		}
	case "babyJubJub":
		err = key.CreateBabyJubJubKeypair()
		if err != nil {
			common.Log.Warningf("failed to create babyjubjub keypair; %s", err.Error())
			return
		}
	case "C25519":
		provide.RenderError("implementation in progress", 422, c)
	}

	if key.Create(db) {
		provide.Render(key, 201, c)
	} else {
		obj := map[string]interface{}{}
		obj["errors"] = key.Errors
		provide.Render(obj, 422, c)
	}
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

	db := dbconf.DatabaseConnection()
	var query *gorm.DB

	query = db.Table("keys").Joins("inner join vaults on keys.vault_id = vaults.id")
	query.Where("id = ? AND vault_id = ?", c.Param("keyId"), c.Param("id"))
	if bearer.ApplicationID != nil && *bearer.ApplicationID != uuid.Nil {
		query = query.Where("vaults.application_id = ?", bearer.ApplicationID)
	} else if bearer.OrganizationID != nil && *bearer.OrganizationID != uuid.Nil {
		query = query.Where("vaults.organization_id = ?", bearer.OrganizationID)
	} else if bearer.UserID != nil && *bearer.UserID != uuid.Nil {
		query = query.Where("vaults.user_id = ?", bearer.UserID)
	}
	query.Find(&key)

	if key.ID == uuid.Nil {
		provide.RenderError("key not found", 404, c)
		return
	}

	signature, err := key.Sign([]byte(*params.Message))
	if err != nil {
		provide.RenderError(err.Error(), 500, c)
		return
	}

	sighex := make([]byte, hex.EncodedLen(len(signature)))
	hex.Encode(sighex, signature)

	provide.Render(&KeySignVerifyRequestResponse{
		Signature: common.StringOrNil(string(sighex)),
	}, 200, c)
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

	db := dbconf.DatabaseConnection()
	var query *gorm.DB

	query = db.Table("keys").Joins("inner join vaults on keys.vault_id = vaults.id")
	query.Where("id = ? AND vault_id = ?", c.Param("keyId"), c.Param("id"))
	if bearer.ApplicationID != nil && *bearer.ApplicationID != uuid.Nil {
		query = query.Where("vaults.application_id = ?", bearer.ApplicationID)
	} else if bearer.OrganizationID != nil && *bearer.OrganizationID != uuid.Nil {
		query = query.Where("vaults.organization_id = ?", bearer.OrganizationID)
	} else if bearer.UserID != nil && *bearer.UserID != uuid.Nil {
		query = query.Where("vaults.user_id = ?", bearer.UserID)
	}
	query.Find(&key)

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

	err = key.Verify([]byte(*params.Message), sig)
	verified := err == nil

	provide.Render(&KeySignVerifyRequestResponse{
		Verified: &verified,
	}, 200, c)
}

func vaultSecretsListHandler(c *gin.Context) {
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

	var secrets []*Secret
	provide.Paginate(c, vault.ListSecretsQuery(db), &Secret{}).Find(&secrets)
	provide.Render(secrets, 200, c)
}
