package glog

const (
	// generic error message
	LV_ERR_DETAIL = 1
	// error stack or DEBUG
	LV_ERR_STACK = 2

	LV_SVR_CONNECT = 1 // server
	LV_LOGIN       = 1 // server
	LV_SVR_OPEN    = 1 // mux
	LV_REQ         = 1 // mux

	LV_CLT_CONNECT = 2 // client
	LV_WARN_EDGE   = 2 // queue

	LV_WARN    = 3 // mux
	LV_TOKEN   = 3 // client, d5
	LV_SESSION = 3 // server

	LV_ACT_FRM    = 4 // mux
	LV_DAT_FRM    = 5 // mux, queue
	LV_TUN_SELECT = 5 // connpool
)
