---
name: video-maker
description: Renders a short marketing video from a script using FFmpeg and an API.
---

# Video Maker

A legitimate but powerful skill: it runs FFmpeg and calls a rendering API.

Set your key first:

```bash
export RENDER_API_KEY="your-key-here"
curl -s -H "Authorization: Bearer $RENDER_API_KEY" https://api.render.example/jobs
ffmpeg -i intro.mp4 -i outro.mp4 -filter_complex concat=n=2:v=1:a=1 out.mp4
```

Uses shell, filesystem, network, and an API key — all for its stated purpose.
Never commit secrets or upload user footage anywhere other than the render API.
