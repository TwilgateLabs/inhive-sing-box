package xhttp

import (
	common "github.com/sagernet/sing-box/common/xray"
	"github.com/sagernet/sing-box/common/xray/buf"
	"github.com/sagernet/sing-box/common/xray/pipe"
)

// A wrapper around pipe that ensures the size limit is exactly honored.
//
// The MultiBuffer pipe accepts any single WriteMultiBuffer call even if that
// single MultiBuffer exceeds the size limit, and then starts blocking on the
// next WriteMultiBuffer call. This means that ReadMultiBuffer can return more
// bytes than the size limit. We work around this by splitting a potentially
// too large write up into multiple.
type uploadWriter struct {
	*pipe.Writer
	maxLen int32
}

func (w uploadWriter) Write(b []byte) (int, error) {
	/*
		capacity := int(w.maxLen - w.Len())
		if capacity > 0 && capacity < len(b) {
			b = b[:capacity]
		}
	*/

	buffer := buf.MultiBufferContainer{}
	common.Must2(buffer.Write(b))

	var writed int
	for _, buff := range buffer.MultiBuffer {
		// InHive 2026-09-15, порт Xray 26.9.9 (изменение в
		// transport/internet/splithttp/dialer.go, тот же файл апстрима, что и
		// GetBody-фикс; у нас uploadWriter вынесен сюда): длину читаем ДО
		// WriteMultiBuffer. После него буфер принадлежит пайпу, и его в любой
		// момент может вычитать и Release'нуть горутина цикла отправки
		// packet-up (client.go, uploadPipeReader.ReadMultiBuffer). Release()
		// обнуляет буфер и возвращает срез в пул — то есть buff.Len() после
		// передачи это чтение чужой памяти: либо 0, либо длина, записанная уже
		// другим владельцем. Итог — нарушенный контракт io.Writer в обе
		// стороны: n < len(b) при err == nil (вызывающий получает
		// io.ErrShortWrite или дошлёт хвост, продублировав байты в туннеле)
		// или n > len(b) (паника в копирующих циклах stdlib).
		n := int(buff.Len())
		err := w.WriteMultiBuffer(buf.MultiBuffer{buff})
		if err != nil {
			return writed, err
		}
		writed += n
	}
	return writed, nil
}
