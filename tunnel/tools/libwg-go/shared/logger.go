package shared

// #cgo LDFLAGS: -llog
// #include <android/log.h>
// #include <stdlib.h>
import "C"
import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"unsafe"

	"github.com/amnezia-vpn/amneziawg-go/device"
	"golang.org/x/sys/unix"
)

func init() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, unix.SIGUSR2)
	go func() {
		buf := make([]byte, os.Getpagesize())
		for {
			select {
			case <-signals:
				n := runtime.Stack(buf, true)
				if n == len(buf) {
					n--
				}
				buf[n] = 0
				tag := C.CString("AmneziaWG/Stacktrace")
				C.__android_log_write(C.ANDROID_LOG_ERROR, tag, (*C.char)(unsafe.Pointer(&buf[0])))
				C.free(unsafe.Pointer(tag))
			}
		}
	}()
}

func sanitize(s string) string {
	return strings.ReplaceAll(s, "\x00", "\\0")
}

func LogDebug(tag string, format string, args ...interface{}) {
	msg := sanitize(fmt.Sprintf(format, args...))
	cTag := C.CString(tag)
	cMsg := C.CString(msg)
	C.__android_log_write(C.ANDROID_LOG_DEBUG, cTag, cMsg)
	C.free(unsafe.Pointer(cTag))
	C.free(unsafe.Pointer(cMsg))
}

func LogError(tag string, format string, args ...interface{}) {
	msg := sanitize(fmt.Sprintf(format, args...))
	cTag := C.CString(tag)
	cMsg := C.CString(msg)
	C.__android_log_write(C.ANDROID_LOG_ERROR, cTag, cMsg)
	C.free(unsafe.Pointer(cTag))
	C.free(unsafe.Pointer(cMsg))
}

func NewLogger(tag string) *device.Logger {
	return &device.Logger{
		Verbosef: func(format string, args ...any) {
			LogDebug(tag, format, args...)
		},
		Errorf: func(format string, args ...any) {
			LogError(tag, format, args...)
		},
	}
}
