package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/vault/common"
)

// AuditLogEvent is the struct containing the audit log fields
type AuditLogEvent struct {
	AuditMessage   *string    `json:"log_type"`
	Timestamp      *time.Time `json:"timestamp"`
	RequestID      *string    `json:"request_id"`
	UserID         *string    `json:"user_id"`
	AppID          *string    `json:"app_id"`
	OrgID          *string    `json:"org_id"`
	RemoteAddress  *string    `json:"remote_address"`
	RequestPath    *string    `json:"path"`
	RequestMethod  *string    `json:"method"`
	Host           *string    `json:"host"`
	ResponseStatus *int       `json:"status,omitempty"`
	Latency        *int64     `json:"latency,omitempty"`
}

// AuditRequest logs data from the http request for audit purposes
func AuditRequest(c *gin.Context, msg string) {

	// set the audit data
	requestID := c.GetString("RequestId")
	timestamp := time.Now().UTC()
	userID := c.GetString("user_id")
	appID := c.GetString("application_id")
	orgID := c.GetString("organization_id")
	remoteAddress := c.Request.RemoteAddr
	requestPath := c.Request.RequestURI
	requestMethod := c.Request.Method
	host := c.Request.Host

	// create the audit event
	auditEvent := &AuditLogEvent{
		AuditMessage:   common.StringOrNil(msg),
		Timestamp:      &timestamp,
		RequestID:      common.StringOrNil(requestID),
		UserID:         common.StringOrNil(userID),
		AppID:          common.StringOrNil(appID),
		OrgID:          common.StringOrNil(orgID),
		RemoteAddress:  common.StringOrNil(remoteAddress),
		RequestPath:    common.StringOrNil(requestPath),
		RequestMethod:  common.StringOrNil(requestMethod),
		Host:           common.StringOrNil(host),
		ResponseStatus: nil,
		Latency:        nil,
	}

	writeAuditLogEvent(auditEvent)
}

func writeAuditLogEvent(event *AuditLogEvent) {
	// log to stdout for the moment, add more options later (like file)
	logEvent, _ := json.Marshal(*event)
	fmt.Fprintln(os.Stdout, string(logEvent))
}

// AuditResponse logs data from the http response for audit purposes
func AuditResponse(c *gin.Context, msg string, start int64) {

	// get the status code of the http response
	statusCode := c.Writer.Status()

	c.Next()

	// set the audit data
	timestamp := time.Now().UTC()
	requestID := c.GetString("RequestId")
	userID := c.GetString("user_id")
	appID := c.GetString("application_id")
	orgID := c.GetString("organization_id")
	remoteAddress := c.Request.RemoteAddr
	requestPath := c.Request.URL.RequestURI()
	requestMethod := c.Request.Method
	host := c.Request.Host
	latency := (time.Now().UnixNano() - start) / 1000000 // latency in milliseconds

	// create the audit event
	auditEvent := &AuditLogEvent{
		AuditMessage:   common.StringOrNil(msg),
		Timestamp:      &timestamp,
		RequestID:      common.StringOrNil(requestID),
		UserID:         common.StringOrNil(userID),
		AppID:          common.StringOrNil(appID),
		OrgID:          common.StringOrNil(orgID),
		RemoteAddress:  common.StringOrNil(remoteAddress),
		RequestPath:    common.StringOrNil(requestPath),
		RequestMethod:  common.StringOrNil(requestMethod),
		Host:           common.StringOrNil(host),
		ResponseStatus: &statusCode,
		Latency:        &latency,
	}

	writeAuditLogEvent(auditEvent)
}

// AuditLogMiddleware logs incoming requests and outgoing responses
func AuditLogMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {

		// Check for incoming header, use it if exists
		requestID := c.Request.Header.Get("X-Request-Id")

		// Create request id with UUID4
		if requestID == "" {
			uuid4, _ := uuid.NewV4()
			requestID = uuid4.String()
		}

		// Expose it for use in the application
		c.Set("RequestId", requestID)

		// Set X-Request-Id header
		c.Writer.Header().Set("X-Request-Id", requestID)

		// start the latency timer
		startTime := time.Now().UnixNano()

		// audit the request
		AuditRequest(c, "Audit:Request")

		// defer the auditing of the response until we have it
		defer AuditResponse(c, "Audit:Response", startTime)
		c.Next()
	}
}
