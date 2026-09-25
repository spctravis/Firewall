package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

const defaultStateFile = "/var/lib/firewallmanager/state.json"

type Config struct {
	IPv6Enabled     bool `json:"ipv6_enabled"`
	DockerEnabled   bool `json:"docker_enabled"`
	EnforceOutbound bool `json:"enforce_outbound"`
}

type Entry struct {
	CIDR      string    `json:"cidr"`
	Comment   string    `json:"comment,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type State struct {
	Config     Config  `json:"config"`
	AllowedIn  []Entry `json:"allowed_in"`
	AllowedOut []Entry `json:"allowed_out"`
	Blocked    []Entry `json:"blocked"`
}

type FirewallApp struct {
	state          State
	stateFile      string
	fyneApp        fyne.App
	window         fyne.Window
	allowedInList  *widget.List
	allowedOutList *widget.List
	blockedList    *widget.List
	statusLabel    *widget.Label
	ipv6Check      *widget.Check
	enforceCheck   *widget.Check
	dockerCheck    *widget.Check
}

func formatEntry(entry Entry) string {
	if strings.TrimSpace(entry.Comment) != "" {
		return fmt.Sprintf("%s  (%s)", entry.CIDR, entry.Comment)
	}
	return entry.CIDR
}

func main() {
	// Elevate to root via pkexec if not already running as root
	ensureRoot()

	a := &FirewallApp{
		stateFile: defaultStateFile,
		fyneApp:   app.NewWithID("com.firewallmanager.app"),
	}

	a.window = a.fyneApp.NewWindow("Firewall Manager")
	a.window.Resize(fyne.NewSize(1000, 800))

	if err := a.loadState(); err != nil {
		a.state = State{
			Config: Config{
				IPv6Enabled:     false,
				DockerEnabled:   true,
				EnforceOutbound: false,
			},
			AllowedIn:  []Entry{},
			AllowedOut: []Entry{},
			Blocked:    []Entry{},
		}
	}

	tabs := container.NewAppTabs(
		container.NewTabItem("Dashboard", a.buildDashboardTab()),
		container.NewTabItem("Allowed In", a.buildAllowedInTab()),
		container.NewTabItem("Allowed Out", a.buildAllowedOutTab()),
		container.NewTabItem("Blocked", a.buildBlockedTab()),
	)

	tabs.SetTabLocation(container.TabLocationLeading)
	a.window.SetContent(tabs)
	a.window.ShowAndRun()
}

func ensureRoot() {
	// Already root: clean up D-Bus env and return
	if os.Geteuid() == 0 {
		os.Unsetenv("DBUS_SESSION_BUS_ADDRESS")
		return
	}

	// Get path of current executable
	execPath, err := os.Executable()
	if err != nil {
		fmt.Printf("Failed to get executable path: %v\n", err)
		os.Exit(1)
	}

	// Pass current user display variables through pkexec
	args := []string{
		"env",
		fmt.Sprintf("DISPLAY=%s", os.Getenv("DISPLAY")),
		fmt.Sprintf("XAUTHORITY=%s", os.Getenv("XAUTHORITY")),
		fmt.Sprintf("WAYLAND_DISPLAY=%s", os.Getenv("WAYLAND_DISPLAY")),
		"DBUS_SESSION_BUS_ADDRESS=",
		execPath,
	}
	args = append(args, os.Args[1:]...)

	cmd := exec.Command("pkexec", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	// Execute elevated process
	if err := cmd.Run(); err != nil {
		fmt.Printf("Authentication failed or cancelled: %v\n", err)
	}

	// Exit unprivileged parent process
	os.Exit(0)
}

func (a *FirewallApp) getFormattedStatus() string {
	return fmt.Sprintf(
		"IPv6 Status: %s\nDocker Visibility: %s\nEnforce Outbound: %s\n\nActive Allowed In Rules: %d\nActive Allowed Out Rules: %d\nActive Blocked Rules: %d",
		boolToStatus(a.state.Config.IPv6Enabled),
		boolToStatus(a.state.Config.DockerEnabled),
		boolToStatus(a.state.Config.EnforceOutbound),
		len(a.state.AllowedIn),
		len(a.state.AllowedOut),
		len(a.state.Blocked),
	)
}

func boolToStatus(b bool) string {
	if b {
		return "Enabled"
	}
	return "Disabled"
}

func (a *FirewallApp) refreshUI() {
	if a.statusLabel != nil {
		a.statusLabel.SetText(a.getFormattedStatus())
	}
	if a.ipv6Check != nil {
		a.ipv6Check.SetChecked(a.state.Config.IPv6Enabled)
	}
	if a.enforceCheck != nil {
		a.enforceCheck.SetChecked(a.state.Config.EnforceOutbound)
	}
	if a.dockerCheck != nil {
		a.dockerCheck.SetChecked(a.state.Config.DockerEnabled)
	}
	if a.allowedInList != nil {
		a.allowedInList.Refresh()
	}
	if a.allowedOutList != nil {
		a.allowedOutList.Refresh()
	}
	if a.blockedList != nil {
		a.blockedList.Refresh()
	}
}

func (a *FirewallApp) buildDashboardTab() *fyne.Container {
	title := widget.NewLabelWithStyle("System Status & Controls", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	a.statusLabel = widget.NewLabel(a.getFormattedStatus())

	settingsTitle := widget.NewLabelWithStyle("Configuration Settings", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	a.ipv6Check = widget.NewCheck("Enable IPv6 Support", func(checked bool) {
		a.state.Config.IPv6Enabled = checked
	})
	a.ipv6Check.SetChecked(a.state.Config.IPv6Enabled)

	a.enforceCheck = widget.NewCheck("Enforce Outbound Restrictions", func(checked bool) {
		a.state.Config.EnforceOutbound = checked
	})
	a.enforceCheck.SetChecked(a.state.Config.EnforceOutbound)

	a.dockerCheck = widget.NewCheck("Docker Visibility Enabled", func(checked bool) {
		a.state.Config.DockerEnabled = checked
	})
	a.dockerCheck.SetChecked(a.state.Config.DockerEnabled)

	saveSettingsBtn := widget.NewButton("Save & Apply Settings", func() {
		if err := a.saveState(); err != nil {
			dialog.ShowError(fmt.Errorf("Failed to save settings: %v", err), a.window)
			return
		}
		if err := a.applyRules(); err != nil {
			dialog.ShowError(fmt.Errorf("Failed to apply nftables rules: %v", err), a.window)
			return
		}
		a.refreshUI()
		dialog.ShowInformation("Success", "Configuration updated and nftables rules applied!", a.window)
	})

	refreshBtn := widget.NewButton("Refresh & Apply Rules", func() {
		if err := a.loadState(); err != nil {
			dialog.ShowError(fmt.Errorf("Failed to load state: %v", err), a.window)
			return
		}

		if err := a.applyRules(); err != nil {
			dialog.ShowError(fmt.Errorf("Failed to apply nftables rules: %v", err), a.window)
			return
		}

		a.refreshUI()
		dialog.ShowInformation("Success", "State loaded and nftables rules successfully applied!", a.window)
	})

	backupTitle := widget.NewLabelWithStyle("Import & Export Settings", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	exportBtn := widget.NewButton("Export Configuration", func() {
		a.exportConfig()
	})

	importBtn := widget.NewButton("Import Configuration", func() {
		a.importConfig()
	})

	settingsBox := container.NewVBox(
		settingsTitle,
		a.ipv6Check,
		a.enforceCheck,
		a.dockerCheck,
		saveSettingsBtn,
	)

	backupBox := container.NewVBox(
		backupTitle,
		container.NewHBox(exportBtn, importBtn),
	)

	return container.NewVBox(
		title,
		widget.NewSeparator(),
		a.statusLabel,
		refreshBtn,
		widget.NewSeparator(),
		settingsBox,
		widget.NewSeparator(),
		backupBox,
	)
}

func (a *FirewallApp) buildAllowedInTab() *fyne.Container {
	title := widget.NewLabelWithStyle("Allowed Inbound Sources", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	a.allowedInList = widget.NewList(
		func() int { return len(a.state.AllowedIn) },
		func() fyne.CanvasObject {
			return widget.NewLabel("000.000.000.000/00")
		},
		func(i widget.ListItemID, o fyne.CanvasObject) {
			if i < len(a.state.AllowedIn) {
				o.(*widget.Label).SetText(formatEntry(a.state.AllowedIn[i]))
			}
		},
	)

	cidrInput := widget.NewEntry()
	cidrInput.SetPlaceHolder("e.g. 192.168.1.0/24")
	commentInput := widget.NewEntry()
	commentInput.SetPlaceHolder("Optional comment")

	addBtn := widget.NewButton("Allow CIDR", func() {
		if cidrInput.Text == "" {
			dialog.ShowError(fmt.Errorf("CIDR cannot be empty"), a.window)
			return
		}

		a.state.AllowedIn = append(a.state.AllowedIn, Entry{
			CIDR:      cidrInput.Text,
			Comment:   commentInput.Text,
			CreatedAt: time.Now(),
		})

		if err := a.saveState(); err != nil {
			dialog.ShowError(err, a.window)
			return
		}

		if err := a.applyRules(); err != nil {
			dialog.ShowError(err, a.window)
			return
		}

		cidrInput.SetText("")
		commentInput.SetText("")
		a.refreshUI()
	})

	form := container.NewVBox(
		widget.NewLabel("Add Trusted Network:"),
		cidrInput,
		commentInput,
		addBtn,
	)

	return container.NewBorder(title, form, nil, nil, a.allowedInList)
}

func (a *FirewallApp) buildAllowedOutTab() *fyne.Container {
	title := widget.NewLabelWithStyle("Allowed Outbound Destinations", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	a.allowedOutList = widget.NewList(
		func() int { return len(a.state.AllowedOut) },
		func() fyne.CanvasObject {
			return widget.NewLabel("000.000.000.000/00")
		},
		func(i widget.ListItemID, o fyne.CanvasObject) {
			if i < len(a.state.AllowedOut) {
				o.(*widget.Label).SetText(formatEntry(a.state.AllowedOut[i]))
			}
		},
	)

	cidrInput := widget.NewEntry()
	cidrInput.SetPlaceHolder("e.g. 8.8.8.8/32")
	commentInput := widget.NewEntry()
	commentInput.SetPlaceHolder("Optional comment")

	addBtn := widget.NewButton("Allow Outbound CIDR", func() {
		if cidrInput.Text == "" {
			dialog.ShowError(fmt.Errorf("CIDR cannot be empty"), a.window)
			return
		}

		a.state.AllowedOut = append(a.state.AllowedOut, Entry{
			CIDR:      cidrInput.Text,
			Comment:   commentInput.Text,
			CreatedAt: time.Now(),
		})

		if err := a.saveState(); err != nil {
			dialog.ShowError(err, a.window)
			return
		}

		if err := a.applyRules(); err != nil {
			dialog.ShowError(err, a.window)
			return
		}

		cidrInput.SetText("")
		commentInput.SetText("")
		a.refreshUI()
	})

	form := container.NewVBox(
		widget.NewLabel("Add Trusted Outbound Destination:"),
		cidrInput,
		commentInput,
		addBtn,
	)

	return container.NewBorder(title, form, nil, nil, a.allowedOutList)
}

func (a *FirewallApp) buildBlockedTab() *fyne.Container {
	title := widget.NewLabelWithStyle("Blocked Networks (Inbound & Outbound)", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	a.blockedList = widget.NewList(
		func() int { return len(a.state.Blocked) },
		func() fyne.CanvasObject {
			return widget.NewLabel("000.000.000.000/00")
		},
		func(i widget.ListItemID, o fyne.CanvasObject) {
			if i < len(a.state.Blocked) {
				o.(*widget.Label).SetText(formatEntry(a.state.Blocked[i]))
			}
		},
	)

	cidrInput := widget.NewEntry()
	cidrInput.SetPlaceHolder("e.g. 10.0.0.0/8")
	commentInput := widget.NewEntry()
	commentInput.SetPlaceHolder("Optional comment")

	addBtn := widget.NewButton("Block CIDR", func() {
		if cidrInput.Text == "" {
			dialog.ShowError(fmt.Errorf("CIDR cannot be empty"), a.window)
			return
		}

		a.state.Blocked = append(a.state.Blocked, Entry{
			CIDR:      cidrInput.Text,
			Comment:   commentInput.Text,
			CreatedAt: time.Now(),
		})

		if err := a.saveState(); err != nil {
			dialog.ShowError(err, a.window)
			return
		}

		if err := a.applyRules(); err != nil {
			dialog.ShowError(err, a.window)
			return
		}

		cidrInput.SetText("")
		commentInput.SetText("")
		a.refreshUI()
	})

	form := container.NewVBox(
		widget.NewLabel("Add Blocked Network:"),
		cidrInput,
		commentInput,
		addBtn,
	)

	return container.NewBorder(title, form, nil, nil, a.blockedList)
}

func (a *FirewallApp) exportConfig() {
	dialog.ShowFileSave(func(writer fyne.URIWriteCloser, err error) {
		if err != nil {
			dialog.ShowError(err, a.window)
			return
		}
		if writer == nil {
			return
		}
		defer writer.Close()

		data, err := json.MarshalIndent(a.state, "", "  ")
		if err != nil {
			dialog.ShowError(fmt.Errorf("Failed to encode configuration: %v", err), a.window)
			return
		}

		_, err = writer.Write(data)
		if err != nil {
			dialog.ShowError(fmt.Errorf("Failed to write file: %v", err), a.window)
			return
		}

		dialog.ShowInformation("Export Success", "Configuration exported successfully!", a.window)
	}, a.window)
}

func (a *FirewallApp) importConfig() {
	dialog.ShowFileOpen(func(reader fyne.URIReadCloser, err error) {
		if err != nil {
			dialog.ShowError(err, a.window)
			return
		}
		if reader == nil {
			return
		}
		defer reader.Close()

		var newState State
		if err := json.NewDecoder(reader).Decode(&newState); err != nil {
			dialog.ShowError(fmt.Errorf("Failed to parse configuration file: %v", err), a.window)
			return
		}

		a.state = newState

		if err := a.saveState(); err != nil {
			dialog.ShowError(fmt.Errorf("Failed to save imported state: %v", err), a.window)
			return
		}

		if err := a.applyRules(); err != nil {
			dialog.ShowError(fmt.Errorf("Imported configuration saved, but failed to apply rules: %v", err), a.window)
		} else {
			dialog.ShowInformation("Import Success", "Configuration imported and nftables rules applied!", a.window)
		}

		a.refreshUI()
	}, a.window)
}

func (a *FirewallApp) applyRules() error {
	var sb strings.Builder

	sb.WriteString("table inet firewallmanager {\n")

	// INBOUND CHAIN
	sb.WriteString("  chain input {\n")
	sb.WriteString("    type filter hook input priority filter; policy accept;\n")

	for _, entry := range a.state.Blocked {
		if strings.Contains(entry.CIDR, ":") {
			if a.state.Config.IPv6Enabled {
				sb.WriteString(fmt.Sprintf("    ip6 saddr %s drop\n", entry.CIDR))
			}
		} else {
			sb.WriteString(fmt.Sprintf("    ip saddr %s drop\n", entry.CIDR))
		}
	}

	for _, entry := range a.state.AllowedIn {
		if strings.Contains(entry.CIDR, ":") {
			if a.state.Config.IPv6Enabled {
				sb.WriteString(fmt.Sprintf("    ip6 saddr %s accept\n", entry.CIDR))
			}
		} else {
			sb.WriteString(fmt.Sprintf("    ip saddr %s accept\n", entry.CIDR))
		}
	}
	sb.WriteString("  }\n")

	// OUTBOUND CHAIN
	sb.WriteString("  chain output {\n")
	sb.WriteString("    type filter hook output priority filter; policy accept;\n")

	for _, entry := range a.state.Blocked {
		if strings.Contains(entry.CIDR, ":") {
			if a.state.Config.IPv6Enabled {
				sb.WriteString(fmt.Sprintf("    ip6 daddr %s drop\n", entry.CIDR))
			}
		} else {
			sb.WriteString(fmt.Sprintf("    ip daddr %s drop\n", entry.CIDR))
		}
	}

	if a.state.Config.EnforceOutbound {
		for _, entry := range a.state.AllowedOut {
			if strings.Contains(entry.CIDR, ":") {
				if a.state.Config.IPv6Enabled {
					sb.WriteString(fmt.Sprintf("    ip6 daddr %s accept\n", entry.CIDR))
				}
			} else {
				sb.WriteString(fmt.Sprintf("    ip daddr %s accept\n", entry.CIDR))
			}
		}
		sb.WriteString("    drop\n")
	}

	sb.WriteString("  }\n")
	sb.WriteString("}\n")

	cmdScript := fmt.Sprintf("nft delete table inet firewallmanager 2>/dev/null; echo '%s' | nft -f -", sb.String())
	cmd := exec.Command("sh", "-c", cmdScript)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nftables error: %s (%v)", string(output), err)
	}

	return nil
}

func (a *FirewallApp) loadState() error {
	data, err := os.ReadFile(a.stateFile)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &a.state)
}

func (a *FirewallApp) saveState() error {
	data, err := json.MarshalIndent(a.state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(a.stateFile, data, 0600)
}
