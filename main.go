// Command pcaptriage-gui is the desktop application.
//
// It is a shell around the same engine the CLI in cmd/pcaptriage uses: the
// window, the menus and the views live here, and every piece of parsing,
// detection and ranking happens in internal/. Neither interface reimplements
// any part of the other.
//
// The main package sits at the module root because that is where the Wails
// toolchain expects it. Nothing else about the repository layout changed to
// accommodate it.
package main

import (
	"context"
	"embed"
	"log"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/menu"
	"github.com/wailsapp/wails/v2/pkg/menu/keys"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/Proxy-IT/pcaptriage/internal/gui"
)

// The Windows resources — icon, manifest and version block — are generated from
// winres/winres.json into rsrc_windows_amd64.syso, which Go links in
// automatically. The .syso is committed, so a normal build needs no extra tool;
// regenerate it only when the resources change.
//
// Wails' own packaging is deliberately not used for this: the version block it
// writes is one Windows can locate but cannot read strings out of, so the whole
// binary reports an empty ProductName and FileDescription. Build the app with
// `wails build -nopackage`; see the README.
//
//go:generate go-winres make --arch amd64

// version is stamped at build time with -ldflags "-X main.version=...".
var version = "dev"

// The whole frontend is embedded, so the app is one file and loads nothing from
// disk or from the network at runtime.
//
//go:embed all:frontend/dist
var assets embed.FS

func main() {
	app := gui.New(version)

	if err := wails.Run(&options.App{
		Title:  "pcaptriage",
		Width:  1080,
		Height: 800,
		// Small enough to still be usable on a laptop, large enough that a
		// finding card is never squeezed into an unreadable column.
		MinWidth:  760,
		MinHeight: 560,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		// The window is a plain surface; the page paints its own background.
		BackgroundColour: &options.RGBA{R: 249, G: 249, B: 247, A: 1},
		OnStartup:        app.Startup,
		Menu:             appMenu(app),
		Bind:             []any{app},
		DragAndDrop: &options.DragAndDrop{
			EnableFileDrop: true,
		},
		Windows: &windows.Options{
			// The webview never navigates anywhere, so there is nothing for a
			// context menu to offer beyond copy on selected text.
			WebviewIsTransparent: false,
			WindowIsTranslucent:  false,
		},
	}); err != nil {
		log.Fatalf("pcaptriage: %v", err)
	}
}

// appMenu builds the application menu.
//
// Normal application chrome is part of the first-launch design: a window with a
// single drop target and no menu reads as a utility fragment rather than an
// application.
func appMenu(app *gui.App) *menu.Menu {
	m := menu.NewMenu()

	fileMenu := m.AddSubmenu("File")
	fileMenu.AddText("Open capture…", keys.CmdOrCtrl("o"), func(*menu.CallbackData) {
		wruntime.EventsEmit(appCtx(app), gui.EventOpenRequested)
	})
	fileMenu.AddSeparator()
	fileMenu.AddText("Quit", keys.CmdOrCtrl("q"), func(*menu.CallbackData) {
		wruntime.Quit(appCtx(app))
	})

	helpMenu := m.AddSubmenu("Help")
	helpMenu.AddText("About pcaptriage", nil, func(*menu.CallbackData) {
		wruntime.EventsEmit(appCtx(app), gui.EventShowAbout)
	})

	return m
}

// appCtx returns the runtime context once Wails has provided it. Menu
// callbacks cannot fire before startup, so this is never nil in practice.
func appCtx(app *gui.App) context.Context { return app.Context() }
