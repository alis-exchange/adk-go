package agui

import (
	"google.golang.org/adk/cmd/launcher"
	"google.golang.org/adk/cmd/launcher/universal"
	"google.golang.org/adk/cmd/launcher/web"
	webagui "google.golang.org/adk/cmd/launcher/web/agui"
)

// NewLauncher returns a launcher capable of serving queries from AgentEngine.
func NewLauncher(appName string, opts ...webagui.Option) launcher.Launcher {
	return universal.NewLauncher(web.NewLauncher(webagui.NewLauncher(appName, opts...)))
}
