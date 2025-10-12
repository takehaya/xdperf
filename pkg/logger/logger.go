package logger

import (
	"context"
	"errors"
	"os"
	"runtime"
	"syscall"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Config struct {
	JSON      bool `default:"false"` // trueならJSONフォーマット
	NoColor   bool `default:"false"` // trueなら色付けしない
	Verbose   int  `default:"0"`     // 0はInfo相当 1以上でDebug
	Quiet     bool `default:"false"` // trueでWarn以上に引き上げる
	AddCaller bool `default:"false"` // trueならログに呼び出し元情報を追加する
}

func NewLogger(cfg Config) (*zap.Logger, func(context.Context) error, error) {
	encCfg := zapcore.EncoderConfig{
		TimeKey:        "ts",
		LevelKey:       "level",
		MessageKey:     "msg",
		CallerKey:      "caller",
		EncodeTime:     func(t time.Time, enc zapcore.PrimitiveArrayEncoder) { enc.AppendString(t.Format(time.RFC3339)) },
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	var enc zapcore.Encoder
	if cfg.JSON {
		enc = zapcore.NewJSONEncoder(encCfg)
	} else {
		if cfg.NoColor || runtime.GOOS == "windows" {
			encCfg.EncodeLevel = zapcore.CapitalLevelEncoder
		} else {
			encCfg.EncodeLevel = zapcore.CapitalColorLevelEncoder
		}
		enc = zapcore.NewConsoleEncoder(encCfg)
	}

	// CLIなので標準エラー出力にログを出す
	ws := zapcore.AddSync(os.Stderr)

	level := zapcore.InfoLevel
	if cfg.Quiet {
		level = zapcore.WarnLevel
	}
	if cfg.Verbose > 0 && !cfg.Quiet {
		level = zapcore.DebugLevel
	}

	core := zapcore.NewCore(enc, ws, level)

	opts := []zap.Option{
		zap.ErrorOutput(ws),
		zap.AddStacktrace(zapcore.ErrorLevel),
	}
	if cfg.AddCaller || level == zapcore.DebugLevel {
		opts = append(opts, zap.AddCaller())
	}

	lg := zap.New(core, opts...)

	cleanup := func(_ context.Context) error {
		if err := lg.Sync(); err != nil {
			// 標準出力・標準エラーに対する Sync は多くの環境で EINVAL 等になるため無視する
			if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EBADF) {
				return nil
			}
			return err
		}
		return nil
	}
	return lg, cleanup, nil
}
