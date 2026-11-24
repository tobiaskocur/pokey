# Pokey brand

The mark is a curious hedgehog sniffing a file inside a quarantine frame.

## Files

| Path | What | Use |
| --- | --- | --- |
| `appicon/AppIcon.icon/` | Icon Composer source: `icon.json` and three 1024×1024 SVG layers (`1-hedgehog`, `2-face`, `3-quarantine`, back to front); the background gradient is in `icon.json` | Xcode 26+, macOS 26 |
| `appicon/AppIcon.appiconset/` | `Contents.json` and 10 PNGs: 16, 32, 128, 256, 512 pt at @1x and @2x | asset catalog, macOS 15 and older |
| `appicon/appicon.svg`, `appicon-1024/512/256/128.png` | finished icon shape (824 px body on a 1024 canvas, with shadow) | web, README, docs |
| `appicon/appicon-small.svg` | simplified drawing for 16 and 32 px (no frame) | source of the small sizes |
| `appicon/appicon-fullbleed.svg`, `-1024.png` | square without mask or shadow, all layers merged | checks, other tools |
| `mark/mark.svg`, `mark-512.png`, `mark-1024.png` | mark on a transparent background | light backgrounds |
| `menubar/menubar-template.svg`, `menubarTemplate.png`, `menubarTemplate@2x.png` | 18×18 pt template icon, black and alpha only | `NSImage.isTemplate = true` or asset "Render As: Template Image" |
| `wordmark/wordmark-light.svg/.png` | "pokey" in brown `#4A2F22` | light backgrounds |
| `wordmark/wordmark-dark.svg/.png` | "pokey" in cream `#FFF4E6` | dark backgrounds |
| `wordmark/lockup-light.svg/.png` | mark and wordmark | light backgrounds |
| `wordmark/lockup-dark.svg/.png` | icon tile and wordmark | dark backgrounds (brown quills disappear on dark) |
| `social/social-preview.png` (`.svg`) | GitHub social preview, 1280×640 | GitHub → Settings → Social preview |
| `fonts/OFL-Fredoka.txt` | font license | |

All text is converted to outlines; there is no font to install or ship.

## Colours

| Name | Hex | Use |
| --- | --- | --- |
| Background top | `#FFEBCB` | icon gradient, top |
| Background bottom | `#FFC27D` | icon gradient, bottom |
| Quills | `#4A2F22` | quills, wordmark on light |
| Fur | `#7B5137` | body, subtitle |
| Feet | `#3A2418` | feet |
| Face | `#F6D7AE` | face, ear |
| Ear | `#EFA889` | inner ear |
| Ink | `#2B1A12` | eyes, nose, mouth |
| Cheek | `#F0907A` | cheek (75 % opacity) |
| Accent | `#E2672B` | quarantine frame, brand accent |
| Cream | `#FFF4E6` | wordmark on dark |

## Rules

- Clear space around the mark, wordmark and lockup: at least the height of the wordmark's "o" on every side.
- Minimum width: mark 48 px, wordmark 64 px, lockup 120 px. Below 48 px use the app icon (16 and 32 px have their own simplified drawing) or the menu bar template icon.
- Menu bar: template icon only, never in colour. macOS tints it for light, dark and highlighted states.
- Do not rotate, distort or recolour the icon, and do not add shadows, outlines or gloss. macOS 26 adds its own.
- The wordmark is lowercase: "pokey". In running text the app is "Pokey".

## Not verified

- `icon.json` is hand-written from the format of Apple's Icon Composer demo project. The background gradient format (`linear-gradient` with `orientation`) is not in that demo and is unverified. Open `AppIcon.icon` in Icon Composer on a Mac, check the Default, Dark, Clear and Tinted previews and save; Icon Composer rewrites the file in its current format.
- `AppIcon.appiconset` follows the Big Sur template (824 px body, 100 px margin, shadow). The corner is a superellipse with n = 5, an approximation of Apple's continuous corner.
- The menu bar template icon was only checked in a simulated dark menu bar, not on macOS. Pokey does not have a menu bar item yet.

## Credits

- Font: Fredoka SemiBold (wordmark) and Fredoka variable (social preview subtitle), SIL Open Font License 1.1, © 2016 The Fredoka Project Authors, from [google/fonts](https://github.com/google/fonts). Full text in `fonts/OFL-Fredoka.txt`.
- The illustration is hand-written SVG; no stock art or image generators.
