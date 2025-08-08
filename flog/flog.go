package flog

type logger interface {
	Debug(v ...interface{})
}
type Flog struct {
}
