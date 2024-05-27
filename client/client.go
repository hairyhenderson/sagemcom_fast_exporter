package client

import (
	"bufio"
	"context"
	"crypto/md5" //nolint:gosec // MD5 is used for compatibility with the device API
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

//nolint:gochecknoglobals
var tracer = otel.Tracer("github.com/hairyhenderson/sagemcom_fast_exporter/client")

// Scraper is an interface for scraping data from a Sagemcom F@st device
type Scraper interface {
	// GetValue retrieves a value from the device using a given XPath.
	GetValue(ctx context.Context, xpath string) (*ValueResponse, error)
	// GetResourceUsage retrieves resource usage from the device.
	GetResourceUsage(ctx context.Context) (*ResourceUsage, error)

	// TODO: add the rest of client's methods here when they're needed
}

//nolint:govet // field alignment
type client struct {
	hc *http.Client

	username     string
	passwordHash string
	authMethod   string
	host         string

	refreshInterval time.Duration
	lastRefresh     time.Time

	// session state
	serverNonce string
	requestID   int
	sessionID   int
	loginMutex  sync.Mutex
}

func New(host, username, password, authMethod string, hc *http.Client, refresh time.Duration) Scraper {
	if hc == nil {
		hc = http.DefaultClient
	}

	c := &client{
		host:       host,
		username:   username,
		authMethod: authMethod,

		loginMutex:   sync.Mutex{},
		requestID:    -1,
		serverNonce:  "",
		passwordHash: generateHash(password, authMethod),

		refreshInterval: refresh,

		hc: hc,
	}

	return c
}

func (c *client) incrementRequestID() int {
	c.requestID++

	return c.requestID
}

// generateNonce generates a random nonce to avoid replay attacks
func generateNonce() int {
	//nolint:gosec // we don't need cryptographically secure random numbers here
	return rand.IntN(500000)
}

// generateHash - Hash value with selected encryption method and return HEX value.
func generateHash(value, authMethod string) string {
	if authMethod == "" {
		authMethod = EncryptionMethodMD5
	}

	b := []byte(value)

	var sum []byte

	switch authMethod {
	case EncryptionMethodMD5:
		//nolint:gosec // MD5 is used for compatibility with the device API
		s := md5.Sum(b)
		sum = s[:]
	case EncryptionMethodSHA512:
		s := sha512.Sum512(b)
		sum = s[:]
	default:
		return value
	}

	return hex.EncodeToString(sum)
}

func (c *client) getCredentialHash() string {
	cred := fmt.Sprintf("%s:%s:%s", c.username, c.serverNonce, c.passwordHash)

	return generateHash(cred, c.authMethod)
}

func (c *client) generateAuthKey(nonce, requestID int) string {
	credentialHash := c.getCredentialHash()
	authString := fmt.Sprintf("%s:%d:%d:JSON:%s",
		credentialHash,
		requestID,
		nonce, apiEndpoint)

	return generateHash(authString, c.authMethod)
}

func (c *client) apiRequestWithRefresh(ctx context.Context, actions []action) (map[string]responseBody, error) {
	ctx, span := tracer.Start(ctx, "SagemcomClient.apiRequestWithRefresh", trace.WithAttributes(
		attribute.String("lastRefresh", c.lastRefresh.Format(time.RFC3339)),
		attribute.String("refreshInterval", c.refreshInterval.String()),
	))
	defer span.End()

	if time.Since(c.lastRefresh) >= c.refreshInterval {
		slog.DebugContext(ctx, "refresh required, refreshing",
			slog.Duration("refresh_interval", c.refreshInterval),
			slog.Time("last_refresh", c.lastRefresh),
			slog.Int("session_id", c.sessionID),
		)

		err := c.Refresh(ctx)
		if err != nil {
			return nil, fmt.Errorf("refresh: %w", err)
		}
	}

	r, err := c.apiRequest(ctx, actions)
	if err != nil && !errors.Is(err, context.Canceled) {
		slog.WarnContext(ctx, "error encountered, retrying", slog.Any("err", err))

		// session expired (perhaps due to UI action), try again
		if logoutErr := c.Logout(ctx); logoutErr != nil {
			slog.ErrorContext(ctx, "logout failed", slog.Any("err", logoutErr))
		}

		err = c.Login(ctx)
		if err != nil {
			slog.ErrorContext(ctx, "retry failed", slog.Any("err", err))

			return nil, fmt.Errorf("login: %w", err)
		}

		return c.apiRequest(ctx, actions)
	}

	return r, err
}

//nolint:gocyclo,funlen
func (c *client) apiRequest(ctx context.Context, actions []action) (map[string]responseBody, error) {
	ctx, span := tracer.Start(ctx, "SagemcomClient.apiRequest", trace.WithAttributes(
		attribute.Int("numActions", len(actions)),
	))
	defer span.End()

	// short-circuit if context is already cancelled
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	requestID := c.incrementRequestID()
	nonce := generateNonce()
	authKey := c.generateAuthKey(nonce, requestID)

	slog.DebugContext(ctx, "request",
		slog.Int("session_id", c.sessionID),
		slog.Int("request_id", requestID),
	)

	u := "http://" + c.host + apiEndpoint

	payload := map[string]requestBody{
		"request": {
			ID:        requestID,
			SessionID: c.sessionID,
			Priority:  false,
			Actions:   actions,
			Cnonce:    nonce,
			AuthKey:   authKey,
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	// prefix the JSON body with 'req='
	values := url.Values{}
	values.Set("req", string(body))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("client.Do: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("readAll: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status %d: %s", resp.StatusCode, respBody)
	}

	var result map[string]responseBody
	if err = json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	reply := result["reply"]

	// these errors count as "no error" for our purposes
	if reply.Error == nil || errors.Is(reply.Error, ErrNoError) || errors.Is(reply.Error, ErrRequestNoError) {
		return result, nil
	}

	err = fmt.Errorf("reply error: %w", reply.Error)

	// Error in one of the actions
	if errors.Is(err, ErrRequestAction) {
		var errs []error

		for _, action := range reply.Actions {
			if action.Error != nil {
				if errors.Is(action.Error, ErrNoError) {
					continue
				}

				errs = append(errs, action.Error)
			}
		}

		if len(errs) > 0 {
			return result, fmt.Errorf("action error(s): %w", errors.Join(errs...))
		}
	}

	return result, fmt.Errorf("unknown error: %w", err)
}

// loginAction - generate the login action
func loginAction(username string) action {
	return action{
		Method: "logIn",
		Parameters: map[string]any{
			"user":       username,
			"persistent": true,
			"session-options": sessionOptions{
				Nss: []nss{
					{
						Name: "gtw",
						URI:  "http://sagemcom.com/gateway-data",
					},
				},
				Language: "ident",
				ContextFlags: contextFlags{
					GetContentName: true,
					LocalTime:      true,
				},
				CapabilityDepth: 2,
				CapabilityFlags: capabilityFlags{
					Name:         true,
					DefaultValue: false,
					Restriction:  true,
					Description:  false,
				},
				TimeFormat:               "ISO_8601",
				WriteOnlyString:          "_XMO_WRITE_ONLY_",
				UndefinedWriteOnlyString: "_XMO_UNDEFINED_WRITE_ONLY_",
			},
		},
	}
}

func (c *client) Login(ctx context.Context) error {
	ctx, span := tracer.Start(ctx, "SagemcomClient.Login")
	defer span.End()

	// make sure we don't have concurrent logins
	c.loginMutex.Lock()
	defer c.loginMutex.Unlock()

	actions := []action{loginAction(c.username)}

	// reset session state
	c.sessionID = -1
	c.serverNonce = ""
	c.requestID = -1

	result, err := c.apiRequest(ctx, actions)
	if err != nil {
		return fmt.Errorf("apiRequest: %w", err)
	}

	response := result["reply"].Actions[0].Callbacks[0].Parameters

	if response == nil {
		return fmt.Errorf("unauthorized: %#v", result)
	}

	if nonceMsg, ok := response["nonce"]; ok {
		var nonce string

		err = json.Unmarshal(nonceMsg, &nonce)
		if err != nil {
			return fmt.Errorf("unmarshal nonce: %w", err)
		}

		c.serverNonce = nonce
	} else {
		return fmt.Errorf("nonce is not a string: %#v", response["nonce"])
	}

	if idMsg, ok := response["id"]; ok {
		var id int

		err = json.Unmarshal(idMsg, &id)
		if err != nil {
			return fmt.Errorf("unmarshal id: %w", err)
		}

		c.sessionID = id
	} else {
		return fmt.Errorf("id is not an int or float64: %v (%T)", response["id"], response["id"])
	}

	c.lastRefresh = time.Now()

	slog.Default().InfoContext(ctx, "logged in", slog.Any("session_id", c.sessionID))

	return nil
}

func (c *client) Refresh(ctx context.Context) error {
	ctx, span := tracer.Start(ctx, "SagemcomClient.Refresh")
	defer span.End()

	if c.sessionID > 0 {
		if err := c.Logout(ctx); err != nil && !errors.Is(err, ErrInvalidSession) {
			slog.WarnContext(ctx, "refresh logout failed, continuing with login", slog.Any("err", err))
		}
	}

	// refresh session
	err := c.Login(ctx)
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}

	return nil
}

func (c *client) Logout(ctx context.Context) error {
	ctx, span := tracer.Start(ctx, "SagemcomClient.Logout")
	defer span.End()

	c.loginMutex.Lock()
	defer c.loginMutex.Unlock()

	actions := []action{
		{
			ID:     0,
			Method: "logOut",
		},
	}

	_, err := c.apiRequest(ctx, actions)
	if err != nil {
		return fmt.Errorf("apiRequest: %w", err)
	}

	c.sessionID = -1
	c.serverNonce = ""
	c.requestID = -1

	return nil
}

// GetValue - port of python's get_value_by_xpath
// Retrieve raw value from router using XPath.
func (c *client) GetValue(ctx context.Context, xpath string) (*ValueResponse, error) {
	ctx, span := tracer.Start(ctx, "SagemcomClient.GetValue")
	defer span.End()

	actions := []action{
		{
			ID:     0,
			Method: "getValue",
			XPath:  url.PathEscape(xpath),
		},
	}

	result, err := c.apiRequestWithRefresh(ctx, actions)
	if err != nil {
		return nil, fmt.Errorf("apiRequestWithRefresh: %w", err)
	}

	if reply, ok := result["reply"]; ok {
		if len(reply.Actions) == 0 {
			return nil, errors.New("no actions in reply")
		}

		action := reply.Actions[0]

		if len(action.Callbacks) == 0 {
			return nil, errors.New("no callbacks in reply")
		}

		value := action.Callbacks[0].Parameters["value"]

		// now we need to convert the value to a *valueResponse
		vr := ValueResponse{}

		err = json.Unmarshal(value, &vr)
		if err != nil {
			return nil, fmt.Errorf("unmarshal value: %w", err)
		}

		return &vr, nil
	}

	return nil, errors.New("no reply in result")
}

// SetValue - port of python's set_value_by_xpath
// Retrieve raw value from router using XPath.
// xpath: path expression
// options: optional options
func (c *client) SetValue(ctx context.Context, xpath, value string) (any, error) {
	actions := []action{
		{
			ID:     0,
			Method: "setValue",
			XPath:  url.PathEscape(xpath),
			Parameters: map[string]any{
				"value": value,
			},
		},
	}

	result, err := c.apiRequestWithRefresh(ctx, actions)
	if err != nil {
		return result, fmt.Errorf("apiRapiRequestWithRefreshequest: %w", err)
	}

	if reply, ok := result["reply"]; ok {
		if len(reply.Actions) == 0 {
			return reply, errors.New("no actions in reply")
		}

		action := reply.Actions[0]

		if len(action.Callbacks) == 0 {
			return action, errors.New("no callbacks in reply")
		}

		value := action.Callbacks[0].Parameters["value"]

		return value, nil
	}

	return result, errors.New("no reply in result")
}

// GetValues - port of python's get_values_by_xpaths
// Retrieve raw values from router using XPath.
// xpaths: Dict of key to path expression
// options: optional options
func (c *client) GetValues(ctx context.Context, xpaths map[string]string) (map[string]any, error) {
	actions := make([]action, 0, len(xpaths))
	for _, xpath := range xpaths {
		actions = append(actions, action{
			ID:     len(actions),
			Method: "getValue",
			XPath:  url.PathEscape(xpath),
		})

		fmt.Printf("actions: %#v\n", actions)
	}

	_, err := c.apiRequestWithRefresh(ctx, actions)
	if err != nil {
		return nil, fmt.Errorf("apiRequestWithRefresh: %w", err)
	}

	// reply := result["reply"]

	// values := make(map[string]any, len(xpaths))
	// for i, action := range reply.Actions {
	// 	values[action.Id] = action.Callbacks[0].Parameters.Value
	// }

	return nil, errors.New("not implemented")
}

// getVendorLogDownloadURI
// Retrieve URI for downloading vendor log.
func (c *client) GetVendorLogDownloadURI(ctx context.Context) (string, error) {
	actions := []action{
		{
			ID:     0,
			Method: "getVendorLogDownloadURI",
			// XPath:      "Device/DeviceInfo/VendorLogFiles/VendorLogFile[@uid='1']",
			XPath: "Device/DeviceInfo/VendorLogFiles/VendorLogFile",
			Parameters: map[string]any{
				"FileName": "utilsLogFile",
			},
		},
	}

	result, err := c.apiRequestWithRefresh(ctx, actions)
	if err != nil {
		return "", fmt.Errorf("apiRequestWithRefresh: %w", err)
	}

	if reply, ok := result["reply"]; ok {
		if len(reply.Actions) == 0 {
			return "", errors.New("no actions in reply")
		}

		action := reply.Actions[0]

		if len(action.Callbacks) == 0 {
			return "", errors.New("no callbacks in reply")
		}

		value := action.Callbacks[0].Parameters["uri"]

		var uri string

		err = json.Unmarshal(value, &uri)
		if err != nil {
			return "", fmt.Errorf("unmarshal uri: %w", err)
		}

		// uri, ok := value.(string)
		// if !ok {
		// 	return "", fmt.Errorf("uri is not a string: %#v", value)
		// }

		return uri, nil
	}

	return "", errors.New("no reply in result")
}

func (c *client) DownloadLogFile(ctx context.Context) ([]LogLine, error) {
	uri, err := c.GetVendorLogDownloadURI(ctx)
	if err != nil {
		return nil, fmt.Errorf("getVendorLogDownloadURI: %w", err)
	}

	u := "http://" + c.host + uri

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("new http request: %w", err)
	}

	req.Header.Set("Accept", "text/plain, */*; q=0.01")

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http do: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status code: %s", resp.Status)
	}

	sc := bufio.NewScanner(resp.Body)
	sc.Split(bufio.ScanLines)

	var lines []LogLine

	for sc.Scan() {
		// format is like:
		// 01.01.1970 00:00:00 LVL MOD Flag(0|1) Message
		// Flag is a "replacement flag" - uncertain meaning
		parts := strings.SplitN(sc.Text(), " ", 6)
		if len(parts) != 6 {
			return nil, fmt.Errorf("invalid log line: %s", sc.Text())
		}

		lvl, mod, msg := parts[2], parts[3], parts[5]

		// we assume the timezone set on the device is the same as local...
		ts, err := time.ParseInLocation("02.01.2006 15:04:05", parts[0]+" "+parts[1], time.Local)
		if err != nil {
			return nil, fmt.Errorf("parse time: %w", err)
		}

		lines = append(lines, LogLine{
			TS:      ts,
			Level:   levelMap[lvl],
			Module:  mod,
			Message: msg,
		})
	}

	return lines, nil
}

type LogLine struct {
	TS      time.Time
	Level   string
	Module  string
	Message string
}

//nolint:gochecknoglobals
var levelMap = map[string]string{
	"INF": "INFO",
	"WRN": "WARN",
	"ERR": "ERROR",
}

func (c *client) GetDeviceInfo(ctx context.Context) (*DeviceInfo, error) {
	ctx, span := tracer.Start(ctx, "SagemcomClient.GetDeviceInfo")
	defer span.End()

	data, err := c.GetValue(ctx, "Device/DeviceInfo")
	if err != nil {
		return nil, fmt.Errorf("getValue: %w", err)
	}

	return &data.Device.DeviceInfo, nil
}

func (c *client) GetHosts(ctx context.Context) ([]Host, error) {
	data, err := c.GetValue(ctx, "Device/Hosts")
	if err != nil {
		return nil, fmt.Errorf("getValue: %w", err)
	}

	return data.Device.Hosts.Hosts, nil
}

func (c *client) GetEthernetInterfaces(ctx context.Context) ([]EthernetInterface, error) {
	data, err := c.GetValue(ctx, "/Device/Ethernet/Interfaces")
	if err != nil {
		return nil, fmt.Errorf("getValue: %w", err)
	}

	return data.Device.Ethernet.Interfaces, nil
}

func (c *client) GetOpticalInterfaces(ctx context.Context) ([]OpticalInterface, error) {
	data, err := c.GetValue(ctx, "Device/Optical/Interfaces")
	if err != nil {
		return nil, fmt.Errorf("getValue: %w", err)
	}

	return data.Device.Optical.Interfaces, nil
}

//nolint:gocyclo,funlen
func (c *client) GetResourceUsage(ctx context.Context) (*ResourceUsage, error) {
	ctx, span := tracer.Start(ctx, "SagemcomClient.GetResourceUsage")
	defer span.End()

	actions := []action{
		{
			ID: 0,
			// getRessourcesUsage - note that the typo is intentional
			Method: "getRessourcesUsage",
			XPath:  "Device/DeviceInfo",
		},
	}

	result, err := c.apiRequestWithRefresh(ctx, actions)
	if err != nil {
		return nil, fmt.Errorf("apiRequestWithRefresh: %w", err)
	}

	reply, ok := result["reply"]
	if !ok {
		return nil, errors.New("no reply in result")
	}

	if len(reply.Actions) == 0 {
		return nil, errors.New("no actions in reply")
	}

	action := reply.Actions[0]
	if len(action.Callbacks) == 0 {
		return nil, errors.New("no callbacks in reply")
	}

	params := action.Callbacks[0].Parameters
	ru := ResourceUsage{}

	err = json.Unmarshal(params["TotalMemory"], &ru.TotalMemory)
	if err != nil {
		return nil, fmt.Errorf("unmarshal TotalMemory: %w", err)
	}

	err = json.Unmarshal(params["FreeMemory"], &ru.FreeMemory)
	if err != nil {
		return nil, fmt.Errorf("unmarshal FreeMemory: %w", err)
	}

	err = json.Unmarshal(params["AvailableFlashMemory"], &ru.AvailableFlashMemory)
	if err != nil {
		return nil, fmt.Errorf("unmarshal AvailableFlashMemory: %w", err)
	}

	err = json.Unmarshal(params["UsedFlashMemory"], &ru.UsedFlashMemory)
	if err != nil {
		return nil, fmt.Errorf("unmarshal UsedFlashMemory: %w", err)
	}

	err = json.Unmarshal(params["CPUUsage"], &ru.CPUUsage)
	if err != nil {
		return nil, fmt.Errorf("unmarshal CPUUsage: %w", err)
	}

	err = json.Unmarshal(params["LoadAverage"], &ru.LoadAverage)
	if err != nil {
		return nil, fmt.Errorf("unmarshal LoadAverage: %w", err)
	}

	err = json.Unmarshal(params["LoadAverage5"], &ru.LoadAverage5)
	if err != nil {
		return nil, fmt.Errorf("unmarshal LoadAverage5: %w", err)
	}

	err = json.Unmarshal(params["LoadAverage15"], &ru.LoadAverage15)
	if err != nil {
		return nil, fmt.Errorf("unmarshal LoadAverage15: %w", err)
	}

	err = json.Unmarshal(params["ProcessStatus"], &ru.ProcessStatus)
	if err != nil {
		return nil, fmt.Errorf("unmarshal ProcessStatus: %w", err)
	}

	return &ru, nil
}
