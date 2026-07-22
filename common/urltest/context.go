package urltest

import "context"

type contextKeyIsUnifiedDelay struct{}

func ContextWithIsUnifiedDelay(ctx context.Context) context.Context {
	return context.WithValue(ctx, contextKeyIsUnifiedDelay{}, true)
}

func IsUnifiedDelayFromContext(ctx context.Context) bool {
	return ctx.Value(contextKeyIsUnifiedDelay{}) != nil
}

type contextKeyProbeFresh struct{}

// ContextWithProbeFresh помечает контекст пробы как «свежей»: URLTest обязан
// дайлить мимо пула переиспользуемых транспортов через adapter.ProbeFreshDialer
// (см. urltest.go). Ставит clash delay-хендлер при query-параметре fresh=1
// (InHive Dart-клиент шлёт его для НЕ-несущих резидентных серверов).
func ContextWithProbeFresh(ctx context.Context) context.Context {
	return context.WithValue(ctx, contextKeyProbeFresh{}, true)
}

func isProbeFresh(ctx context.Context) bool {
	return ctx.Value(contextKeyProbeFresh{}) != nil
}
