# StackStorm Forensics

## Marceline

An automation pack for [https://github.com/StackStorm|StackStorm]: various actions and ChatOps aliases for file/stream forensics and CTFs challenges.

Although this pack was meant to power Randoms' own CTF helper, Marceline, it can also be reused as a set of independent StackStorm actions or as code somewhere else. Whatever you want, really.

## Commands

So far the list of things Marceline does is really small:
```
base64 decode {{ string }} - Do a base64 decode of a string.
base64 encode {{ string }} - Do a base64 encode of a string.
crack substitution {{ ciphertext }} - Try to crack a substitution cipher.
rot13 {{ string }} - Apply rot13 to a string.
what.s next? - Look for upcoming CTFs.
when is {{ query }}? - Look for upcoming CTFs.
```

However, I'm planning to extend it in the nearest future, and you're more than welcome to contribute.

![](http://i.imgur.com/xxnIghW.gifv)

## Todo

* File analysis: `file`, `hachoir-subfile`
* Metadata extraction: `hachoir-metadata`
* Output from `strings`
* Hash lookups
* Hex/bin/dec/ascii/unicode conversions
* Basic steganographic analysis
* Nmap scanning

Suggestions are always appreciated.

— Ed.
