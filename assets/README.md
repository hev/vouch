# Assets

The Vouch icon is pixel art: a head holding up a gold key.

| File | Use |
| --- | --- |
| `vouch-1024.png` | Source image, 1024×1024 |
| `vouch-160.png` | README header |
| `vouch-cli.png` | Terminal logo in `--help` (kitty graphics), 256×256 |
| `Vouch.icns` | `Vouch.app` icon, the one the Touch ID sheet shows |

The web app's `server/web/assets/icon-*.png` and `apple-touch-icon.png` are
made from the same source. Scale it with nearest-neighbour only, never a
smoothing filter, so the pixels stay sharp. For example, with Pillow:
`Image.open("vouch-1024.png").resize((160, 160), Image.Resampling.NEAREST)`.
