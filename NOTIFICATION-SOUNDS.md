# Custom Notification Sounds

## Adding Sounds

### Option 1: Use Free Sound Libraries
- **Zapsplat**: https://www.zapsplat.com (free with attribution)
- **Freesound**: https://freesound.org
- **Notification Sounds**: https://notificationsounds.com

### Option 2: Convert to Base64
```bash
# Convert sound file to base64
base64 -w 0 notification.mp3 > sound.txt

# Then use in HTML:
# data:audio/mpeg;base64,<paste_base64_here>
```

### Option 3: Host on CDN
Upload to:
- GitHub Pages
- Cloudinary
- ImgBB

## Recommended Sounds
1. iOS Notification: "Tri-tone" sound
2. WhatsApp: "Pop" sound
3. Slack: "Knock" sound
4. Discord: "Deafen" sound
