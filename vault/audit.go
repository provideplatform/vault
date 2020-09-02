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
	AuditMessage   *string    `json:"LogType"`
	Timestamp      *time.Time `json:"Timestamp"`
	RequestID      *string    `json:"RequestID"`
	UserID         *string    `json:"UserID"`
	AppID          *string    `json:"AppID"`
	OrgID          *string    `json:"OrgID"`
	RemoteAddress  *string    `json:"RemoteAddress"`
	RequestPath    *string    `json:"Path"`
	RequestMethod  *string    `json:"Method"`
	Host           *string    `json:"Host"`
	ResponseStatus *int       `json:"Status,omitempty"`
	Latency        *string    `json:"Latency,omitempty"`
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
	latency := fmt.Sprintf("%dms", (time.Now().UnixNano()-start)/1000000)

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
		Latency:        common.StringOrNil(latency),
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
