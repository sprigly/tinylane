package main

// 面板兜底登录：用 /etc/shadow 里 root 的哈希校验（与 LuCI 相同的 root 密码）。
// 纯 Go 实现 crypt(3) 的 $1$（md5crypt）、$5$（sha256crypt）、$6$（sha512crypt）。
// 哈希只在内存里比较，任何情况下都不写日志、不返回给客户端。

import (
	"bufio"
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"hash"
	"os"
	"strconv"
	"strings"
)

const cryptAlphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

var errCryptUnsupported = errors.New("不支持的哈希类型")

func b64From24(out []byte, b2, b1, b0 byte, n int) []byte {
	w := uint(b2)<<16 | uint(b1)<<8 | uint(b0)
	for ; n > 0; n-- {
		out = append(out, cryptAlphabet[w&0x3f])
		w >>= 6
	}
	return out
}

// shaCrypt：Drepper SHA-crypt。返回编码后的哈希部分（不含 $id$salt$ 前缀）。
func shaCrypt(newH func() hash.Hash, pw, salt []byte, rounds int) []byte {
	hs := newH().Size()
	h := newH()
	h.Write(pw)
	h.Write(salt)
	h.Write(pw)
	b := h.Sum(nil)

	h = newH()
	h.Write(pw)
	h.Write(salt)
	for n := len(pw); n > 0; n -= hs {
		if n > hs {
			h.Write(b)
		} else {
			h.Write(b[:n])
		}
	}
	for n := len(pw); n > 0; n >>= 1 {
		if n&1 != 0 {
			h.Write(b)
		} else {
			h.Write(pw)
		}
	}
	a := h.Sum(nil)

	h = newH()
	for i := 0; i < len(pw); i++ {
		h.Write(pw)
	}
	dp := h.Sum(nil)
	p := make([]byte, 0, len(pw))
	for n := len(pw); n > 0; n -= hs {
		if n > hs {
			p = append(p, dp...)
		} else {
			p = append(p, dp[:n]...)
		}
	}

	h = newH()
	for i := 0; i < 16+int(a[0]); i++ {
		h.Write(salt)
	}
	ds := h.Sum(nil)
	s := make([]byte, 0, len(salt))
	for n := len(salt); n > 0; n -= hs {
		if n > hs {
			s = append(s, ds...)
		} else {
			s = append(s, ds[:n]...)
		}
	}

	c := a
	for i := 0; i < rounds; i++ {
		h = newH()
		if i&1 != 0 {
			h.Write(p)
		} else {
			h.Write(c)
		}
		if i%3 != 0 {
			h.Write(s)
		}
		if i%7 != 0 {
			h.Write(p)
		}
		if i&1 != 0 {
			h.Write(c)
		} else {
			h.Write(p)
		}
		c = h.Sum(nil)
	}

	var out []byte
	if hs == 32 {
		order := [][3]int{{0, 10, 20}, {21, 1, 11}, {12, 22, 2}, {3, 13, 23}, {24, 4, 14}, {15, 25, 5}, {6, 16, 26}, {27, 7, 17}, {18, 28, 8}, {9, 19, 29}}
		for _, o := range order {
			out = b64From24(out, c[o[0]], c[o[1]], c[o[2]], 4)
		}
		out = b64From24(out, 0, c[31], c[30], 3)
	} else {
		order := [][3]int{{0, 21, 42}, {22, 43, 1}, {44, 2, 23}, {3, 24, 45}, {25, 46, 4}, {47, 5, 26}, {6, 27, 48}, {28, 49, 7}, {50, 8, 29}, {9, 30, 51}, {31, 52, 10}, {53, 11, 32}, {12, 33, 54}, {34, 55, 13}, {56, 14, 35}, {15, 36, 57}, {37, 58, 16}, {59, 17, 38}, {18, 39, 60}, {40, 61, 19}, {62, 20, 41}}
		for _, o := range order {
			out = b64From24(out, c[o[0]], c[o[1]], c[o[2]], 4)
		}
		out = b64From24(out, 0, 0, c[63], 2)
	}
	return out
}

func md5Crypt(pw, salt []byte) []byte {
	h := md5.New()
	h.Write(pw)
	h.Write(salt)
	h.Write(pw)
	fin := h.Sum(nil)
	h = md5.New()
	h.Write(pw)
	h.Write([]byte("$1$"))
	h.Write(salt)
	for n := len(pw); n > 0; n -= 16 {
		if n > 16 {
			h.Write(fin)
		} else {
			h.Write(fin[:n])
		}
	}
	for n := len(pw); n > 0; n >>= 1 {
		if n&1 != 0 {
			h.Write([]byte{0})
		} else if len(pw) > 0 {
			h.Write(pw[:1])
		}
	}
	fin = h.Sum(nil)
	for i := 0; i < 1000; i++ {
		h = md5.New()
		if i&1 != 0 {
			h.Write(pw)
		} else {
			h.Write(fin)
		}
		if i%3 != 0 {
			h.Write(salt)
		}
		if i%7 != 0 {
			h.Write(pw)
		}
		if i&1 != 0 {
			h.Write(fin)
		} else {
			h.Write(pw)
		}
		fin = h.Sum(nil)
	}
	var out []byte
	for _, o := range [][3]int{{0, 6, 12}, {1, 7, 13}, {2, 8, 14}, {3, 9, 15}, {4, 10, 5}} {
		out = b64From24(out, fin[o[0]], fin[o[1]], fin[o[2]], 4)
	}
	return b64From24(out, 0, 0, fin[11], 2)
}

// cryptVerify：pw 是否匹配 crypt(3) 格式的 stored。不支持的格式返回 errCryptUnsupported。
func cryptVerify(stored, pw string) (bool, error) {
	if len(pw) > 256 {
		return false, nil
	}
	parts := strings.Split(stored, "$")
	// "", id, [rounds=N], salt, hash
	if len(parts) < 4 || parts[0] != "" {
		return false, errCryptUnsupported
	}
	id := parts[1]
	rest := parts[2:]
	rounds := 5000
	if (id == "5" || id == "6") && strings.HasPrefix(rest[0], "rounds=") {
		r, err := strconv.Atoi(strings.TrimPrefix(rest[0], "rounds="))
		if err != nil {
			return false, errCryptUnsupported
		}
		if r < 1000 {
			r = 1000
		}
		if r > 999999999 {
			r = 999999999
		}
		rounds = r
		rest = rest[1:]
	}
	if len(rest) != 2 {
		return false, errCryptUnsupported
	}
	salt, want := rest[0], rest[1]
	var got []byte
	switch id {
	case "1":
		if len(salt) > 8 {
			salt = salt[:8]
		}
		got = md5Crypt([]byte(pw), []byte(salt))
	case "5":
		if len(salt) > 16 {
			salt = salt[:16]
		}
		got = shaCrypt(sha256.New, []byte(pw), []byte(salt), rounds)
	case "6":
		if len(salt) > 16 {
			salt = salt[:16]
		}
		got = shaCrypt(sha512.New, []byte(pw), []byte(salt), rounds)
	default: // $y$ yescrypt / $2b$ 等：本机没有
		return false, errCryptUnsupported
	}
	return subtle.ConstantTimeCompare(got, []byte(want)) == 1, nil
}

// shadowHash：读 shadow 文件里 user 的哈希字段（不打印）。
func shadowHash(path, user string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.SplitN(sc.Text(), ":", 3)
		if len(fs) >= 2 && fs[0] == user {
			return fs[1], nil
		}
	}
	return "", errors.New("shadow 里没有该用户")
}

// verifyShadowPassword：root 没设密码（空/!/*）一律拒绝。
func verifyShadowPassword(path, user, pw string) (bool, error) {
	h, err := shadowHash(path, user)
	if err != nil {
		return false, err
	}
	if h == "" || strings.HasPrefix(h, "!") || strings.HasPrefix(h, "*") || pw == "" {
		return false, errors.New("该用户没有可用的密码")
	}
	return cryptVerify(h, pw)
}
