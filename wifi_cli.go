package main

// `tinyfwd -set-wifi NAME [-set-wifi-5ghz-name NAME5]`: set the Wi-Fi name and password from the command line, for the installer (the password is the first
// line of standard input, never an argument). It runs the same steps as the web page (validate, back up the stock file, write it, restart `wland`, check
// that hostapd came back with the new settings, restore on failure), but synchronously and without the wait for a device to rejoin: nothing is connected
// during a first install, and the installer reports the result itself.

import (
	"bufio"
	"errors"
	"io"
	"os"
	"strings"
)

// ApplySync is Apply without the background goroutine and without the wait for a device to rejoin.
func (m *wifiManager) ApplySync(c wifiChange) (string, error) {
	raw, err := os.ReadFile(m.env.xmlPath)
	if err != nil {
		return "", err
	}
	next, changed, err := applyWifiChange(string(raw), c)
	if err != nil {
		return "", err
	}
	if len(changed) == 0 {
		return "nothing to change", nil
	}
	if _, err := m.backup(raw); err != nil {
		return "", errors.New("could not save a backup, nothing was changed: " + err.Error())
	}
	if err := writeFileAtomic(m.env.xmlPath, []byte(next), 0o755); err != nil {
		return "", errors.New("could not write the settings: " + err.Error())
	}
	if err := m.restartAndCheck(next); err != nil {
		writeFileAtomic(m.env.xmlPath, raw, 0o755)
		msg := "the change did not take (" + err.Error() + "); the previous settings were restored"
		if rerr := m.restartAndCheck(string(raw)); rerr != nil {
			msg += ", but Wi-Fi did not confirm after the restore: " + rerr.Error()
		}
		return "", errors.New(msg)
	}
	return "applied: " + strings.Join(changed, ", "), nil
}

// setWifiCLI applies a name (and, when the first line of in is not empty, a password) to the 2.4 GHz network, and the same password to the 5 GHz one.
// name5 renames the 5 GHz network; empty leaves its name alone. An empty password line keeps the current passwords.
func setWifiCLI(m *wifiManager, name, name5 string, in io.Reader) (string, error) {
	line, _ := bufio.NewReaderSize(io.LimitReader(in, 4096), 4096).ReadString('\n')
	pw := strings.TrimRight(line, "\r\n")
	c := wifiChange{SSID: &name}
	five := fiveChange{}
	if pw != "" {
		c.Password, c.PasswordConfirm = &pw, &pw
		five.Password, five.PasswordConfirm = &pw, &pw
	}
	if name5 != "" {
		five.SSID = &name5
	}
	if five.Password != nil || five.SSID != nil {
		c.Five = &five
	}
	return m.ApplySync(c)
}
