package apns

import (
	"strconv"
)

type ErrPayloadTooLarge struct{ Size, Max int }

func (e ErrPayloadTooLarge) Error() string {
	return "apns: payload is " + strconv.Itoa(e.Size) + " bytes, maximum is " + strconv.Itoa(e.Max)
}

type ErrCollapseIDTooLong struct{ Size, Max int }

func (e ErrCollapseIDTooLong) Error() string {
	return "apns: collapse id is " + strconv.Itoa(e.Size) + " bytes, maximum is " + strconv.Itoa(e.Max)
}
