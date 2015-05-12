package pusher

import (
  "bytes"
  "crypto/hmac"
  "crypto/sha256"
  "encoding/hex"
  "encoding/json"
  "fmt"
  "io/ioutil"

  "appengine/urlfetch"

  "github.com/secretinc/server/common"
  "github.com/secretinc/server/common/integrations"
  "github.com/secretinc/server/core/env"
)

type pusherEvent struct {
  Name     string      `json:"name"`
  Data     interface{} `json:"data"`
  Channel  string      `json:"channel"`
  SocketId string      `json:"socket_id,omitempty"`
}

const (
  noSocketId = ""
  baseUrl    = "https://api.pusherapp.com"
)

func SafeChannelName(name string) string {
  out := ""
  for _, c := range name {
    if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
      c == '-' || c == '_' || c == '=' || c == '@' || c == ',' || c == '.' {
      out = out + string(c)
    } else {
      out = out + "_"
    }
  }
  return out
}

func AppKey(c common.Context) string {
  if env.IsLocal() {
    return integrations.PusherDevKey
  } else if env.IsProd(c) {
    return integrations.PusherProdKey
  }
  return integrations.PusherStagingKey
}

func TriggerEvent(c common.Context, channel, event string, data interface{}) error {
  return triggerEvent(c, channel, event, data, noSocketId)
}

func TriggerEventExcluding(c common.Context, channel, event string, data interface{}, socketId string) error {
  return triggerEvent(c, channel, event, data, socketId)
}

func triggerEvent(c common.Context, channel, event string, data interface{}, socketId string) error {
  if data == nil {
    data = map[string]string{}
  }

  dataBytes, err := json.Marshal(data)
  if err != nil {
    return err
  }

  e := pusherEvent{
    Channel:  channel,
    Name:     event,
    SocketId: socketId,
    Data:     string(dataBytes),
  }

  body, err := json.Marshal(e)
  if err != nil {
    return err
  }

  client := urlfetch.Client(c)
  eventsPath := appPath(c) + "/events"
  params := authParams(c, eventsPath, body)

  url := fmt.Sprintf("%s?%s", appUrl(c)+"/events", params)

  resp, err := client.Post(url, "application/json", bytes.NewBuffer(body))
  if err != nil {
    c.Errorf("Failed sending to pusher: %s", err)
    return err
  }

  defer resp.Body.Close()
  res, err := ioutil.ReadAll(resp.Body)
  if err != nil {
    return err
  }

  if resp.StatusCode != 200 {
    c.Errorf("Unexpected status code: %d with response: %s", resp.StatusCode, string(res))
  }

  return nil
}

func SignWithSecret(c common.Context, s string) string {
  key := appSecret(c)

  c.Debugf("Pusher signing %s with key %s", s, key)

  h := hmac.New(sha256.New, []byte(key))
  h.Write([]byte(s))
  return hex.EncodeToString(h.Sum(nil))
}

func authParams(c common.Context, path string, body []byte) string {
  hash := common.Md5Hash(string(body))
  params := fmt.Sprintf("auth_key=%s&auth_timestamp=%d&auth_version=1.0&body_md5=%s", AppKey(c), common.Now().Unix(), hash)
  key := fmt.Sprintf("POST\n%s\n%s", path, params)
  sig := SignWithSecret(c, key)
  params = fmt.Sprintf("%s&auth_signature=%s", params, sig)
  return params
}

func appUrl(c common.Context) string {
  return fmt.Sprintf("%s%s", baseUrl, appPath(c))
}

func appPath(c common.Context) string {
  return fmt.Sprintf("/apps/%d", appId(c))
}

func appId(c common.Context) int {
  if env.IsLocal() {
    return integrations.PusherDevAppId
  } else if env.IsProd(c) {
    return integrations.PusherProdAppId
  }
  return integrations.PusherStagingAppId
}

func appSecret(c common.Context) string {
  if env.IsLocal() {
    return integrations.PusherDevSecret
  } else if env.IsProd(c) {
    return integrations.PusherProdSecret
  }
  return integrations.PusherStagingSecret
}
