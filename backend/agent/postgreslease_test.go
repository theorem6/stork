package agent

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestKea4Address(t *testing.T) {
	ip, err := kea4Address("3232235777")
	require.NoError(t, err)
	require.Equal(t, "192.168.1.1", ip)

	ip, err = kea4Address("192.0.2.10")
	require.NoError(t, err)
	require.Equal(t, "192.0.2.10", ip)
}

func TestColonHexAndLease6Type(t *testing.T) {
	require.Equal(t, "", colonHex(nil))
	require.Equal(t, "01:0a:ff", colonHex([]byte{0x01, 0x0a, 0xff}))
	require.Equal(t, "IA_NA", lease6TypeName(0))
	require.Equal(t, "IA_TA", lease6TypeName(1))
	require.Equal(t, "IA_PD", lease6TypeName(2))
}

func TestEscapeLike(t *testing.T) {
	require.Equal(t, "", escapeLike(""))
	require.Equal(t, `%100\%%`, escapeLike("100%"))
	require.Equal(t, `%a\_b%`, escapeLike("a_b"))
}
