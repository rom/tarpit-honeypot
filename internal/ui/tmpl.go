package ui

const tmpls = `
{{ define "head" }}<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
{{ if gt (refreshSeconds) 0 }}<meta http-equiv="refresh" content="{{ refreshSeconds }}">{{ end }}
<title>tarpit-honeypot</title>
<!-- Synchronous (not defer) so the theme class lands on <html> BEFORE the body
     parses, avoiding any flash-of-default-theme on themed deployments. -->
<script src="/static/theme.js"></script>
<style>
/* ---- Theme palettes: defaults (light) live on :root, overrides on :root.theme-* ----
 * theme.js sets the theme class on <html> from the tarpit_theme cookie before
 * the body parses; every color below is referenced via var(--*) so themes
 * cascade into every element — headings, tables, charts, badges, bars. */
:root {
  /* Base font size — overridden by :root.size-* below. Driven by the
   * tarpit_size cookie via /static/theme.js. rem-based sizes throughout
   * the stylesheet inherit from this so every text element scales. */
  --font-size-base:14px;
  --bg-page:#fafafa; --bg-surface:#fff; --bg-elevated:#f3f3f3; --bg-code:#f0f0f0; --bg-code-block:#f6f8fa;
  --text:#111; --text-muted:#555; --text-faint:#777; --text-strong:#333; --heading-h2:#444;
  --border:#eee; --border-medium:#e3e3e3; --border-strong:#ddd;
  --link:#1a4f9c; --link-hover-bg:#f7faff;
  --sev-low:#555; --sev-medium:#b36b00; --sev-high:#b00020; --sev-critical:#b00020; --sev-critical-bg:#fff5f5;
  --bar-default:#6b8fb5; --bar-medium:#d59a3a; --bar-high:#c0506a; --bar-critical:#b00020;
  --accent:#1a4f9c; --accent-fg:#fff;
  --success-fg:#1a7f37; --success-bg:#e6f4ea; --success-border:#9bd0ad;
  --warning-fg:#9c5a1a; --warning-bg:#fff4e6; --warning-border:#f0c890; --warning-text:#b36b00;
  --sortable-hover-bg:#ebebeb; --arrow-faint:#bbb;
  --tag-bg:#eef; --tag-border:#cce;
  --tag-warn-bg:#fff0e6; --tag-warn-border:#f0c8a0;
  --tag-bad-bg:#ffe9ec; --tag-bad-border:#f0a8b4;
  --host-border:#ccd; --svc-bg:#f0f3f8; --svc-border:#dde3ec;
  --blockquote-bg:#f7f8fa;
  --counter-num:#2c3e50;
  --chart-grid:#eef1f5; --chart-axis-text:#555; --chart-axis-text-faint:#777;
  --chart-edge:#cbd3df; --chart-node-default:#6b8fb5; --chart-node-stroke:#fff;
  --chart-cell-text:#234; --chart-cell-text-hi:#fff;
  --chart-ocean-fill:#f3f7fb; --chart-ocean-stroke:#dde6f0;
  --chart-graticule:#e1e9f2; --chart-graticule-label:#aab4c0;
  --chart-replay-bg:#1e1e2e; --chart-replay-text:#cdd6f4;
  --chart-replay-stale:#a6adc8; --chart-replay-ts:#6c7086;
  --proto-tcp:#4a6fa5; --proto-udp:#b07d2a; --proto-icmp:#2a9d4a; --proto-l2:#7a5cc0; --proto-default:#6a6f7a;
  --pcard-mode-banner:#2a9d4a; --pcard-mode-tarpit:#b00020; --pcard-mode-drop:#888;
  --ctag-bg:#f0f0f0; --ctag-border:#ddd; --ctag-text:#555;
  --ctag-tls-bg:#e6f0ff; --ctag-tls-border:#b8d0f0; --ctag-tls-fg:#1a4f9c;
  --help-badge-bg:#8a93a0; --help-badge-hover-bg:#4a6fa5;
  --widget-toggle-bg:#f3f5f8; --widget-toggle-fg:#556; --widget-toggle-border:#ccd;
  /* JS palette + heatmap ramp + severity (read by charts.js via getComputedStyle) */
  --palette-1:#4a6fa5; --palette-2:#b35900; --palette-3:#2a9d4a; --palette-4:#9c4f96; --palette-5:#c0506a;
  --palette-6:#1a8f9c; --palette-7:#b08a00; --palette-8:#6a6f7a; --palette-9:#7a5cc0; --palette-10:#3a7d3a;
  --ramp-0:#f7fbff; --ramp-1:#dbe9f6; --ramp-2:#b3d3ea; --ramp-3:#7fb0d6; --ramp-4:#4a86bd; --ramp-5:#2a5f9e; --ramp-6:#143e7a;
  --heatmap-zero:#f4f6f9;
}
/* Dark — slate-gray surfaces, light text. */
:root.theme-dark {
  --bg-page:#1a1d23; --bg-surface:#23262e; --bg-elevated:#2a2e36; --bg-code:#2a2e36; --bg-code-block:#1f2229;
  --text:#e0e2e6; --text-muted:#9aa0a8; --text-faint:#757b85; --text-strong:#c3c8d0; --heading-h2:#b0b6c0;
  --border:#3a3e46; --border-medium:#3a3e46; --border-strong:#4a4e58;
  --link:#82a8d8; --link-hover-bg:#2a3140;
  --sev-low:#9aa0a8; --sev-medium:#e0a44a; --sev-high:#e0707a; --sev-critical:#ff5a72; --sev-critical-bg:#3a2026;
  --bar-default:#6b8fb5; --bar-medium:#d59a3a; --bar-high:#c0506a; --bar-critical:#d63c4e;
  --accent:#82a8d8; --accent-fg:#0e1116;
  --success-fg:#6cc78e; --success-bg:#1d3024; --success-border:#2e5538;
  --warning-fg:#e0a44a; --warning-bg:#3a2d18; --warning-border:#6a4d20; --warning-text:#e0a44a;
  --sortable-hover-bg:#2d313a; --arrow-faint:#5a606a;
  --tag-bg:#2a3140; --tag-border:#3d4658;
  --tag-warn-bg:#3a2d18; --tag-warn-border:#6a4d20;
  --tag-bad-bg:#3a2026; --tag-bad-border:#6a3036;
  --host-border:#4a4e58; --svc-bg:#2a3140; --svc-border:#3d4658;
  --blockquote-bg:#23262e;
  --counter-num:#e5eaf0;
  --chart-grid:#2e323a; --chart-axis-text:#9aa0a8; --chart-axis-text-faint:#757b85;
  --chart-edge:#4a4e58; --chart-node-default:#6b8fb5; --chart-node-stroke:#23262e;
  --chart-cell-text:#e0e2e6; --chart-cell-text-hi:#fff;
  --chart-ocean-fill:#1d2129; --chart-ocean-stroke:#2a2f3a;
  --chart-graticule:#2a2f3a; --chart-graticule-label:#5a6068;
  --proto-tcp:#6b8fb5; --proto-udp:#d59a3a; --proto-icmp:#4ab06a; --proto-l2:#9a7cd0; --proto-default:#8a93a0;
  --pcard-mode-banner:#4ab06a; --pcard-mode-tarpit:#d63c4e; --pcard-mode-drop:#6a6f7a;
  --ctag-bg:#2a2e36; --ctag-border:#3a3e46; --ctag-text:#b0b6c0;
  --ctag-tls-bg:#1f2a3a; --ctag-tls-border:#2a3a5a; --ctag-tls-fg:#82a8d8;
  --help-badge-bg:#6a6f7a; --help-badge-hover-bg:#82a8d8;
  --widget-toggle-bg:#2a2e36; --widget-toggle-fg:#9aa0a8; --widget-toggle-border:#3a3e46;
  --palette-1:#82a8d8; --palette-2:#e0a44a; --palette-3:#6cc78e; --palette-4:#c896d8; --palette-5:#e0707a;
  --palette-6:#6ac4cf; --palette-7:#d6c060; --palette-8:#a0a6b0; --palette-9:#a48cd8; --palette-10:#7fb380;
  --ramp-0:#1f2229; --ramp-1:#23303f; --ramp-2:#2a4258; --ramp-3:#365b80; --ramp-4:#4a78a8; --ramp-5:#6094c0; --ramp-6:#82b0d8;
  --heatmap-zero:#1f2229;
}
/* Solarized Dark — solarized.github.io palette. */
:root.theme-solarized-dark {
  --bg-page:#002b36; --bg-surface:#073642; --bg-elevated:#08404f; --bg-code:#073642; --bg-code-block:#052731;
  --text:#93a1a1; --text-muted:#839496; --text-faint:#657b83; --text-strong:#b6c1c1; --heading-h2:#93a1a1;
  --border:#0a4a5b; --border-medium:#0a4a5b; --border-strong:#155666;
  --link:#268bd2; --link-hover-bg:#08404f;
  --sev-low:#839496; --sev-medium:#b58900; --sev-high:#cb4b16; --sev-critical:#dc322f; --sev-critical-bg:#2a1518;
  --bar-default:#268bd2; --bar-medium:#b58900; --bar-high:#cb4b16; --bar-critical:#dc322f;
  --accent:#268bd2; --accent-fg:#fdf6e3;
  --success-fg:#859900; --success-bg:#1a2a18; --success-border:#2a4020;
  --warning-fg:#b58900; --warning-bg:#2a2418; --warning-border:#4a3a20; --warning-text:#b58900;
  --sortable-hover-bg:#0a4858; --arrow-faint:#586e75;
  --tag-bg:#07303a; --tag-border:#155666;
  --tag-warn-bg:#2a2418; --tag-warn-border:#4a3a20;
  --tag-bad-bg:#2a1518; --tag-bad-border:#5a2025;
  --host-border:#155666; --svc-bg:#07303a; --svc-border:#155666;
  --blockquote-bg:#073642;
  --counter-num:#fdf6e3;
  --chart-grid:#093744; --chart-axis-text:#839496; --chart-axis-text-faint:#657b83;
  --chart-edge:#155666; --chart-node-default:#268bd2; --chart-node-stroke:#002b36;
  --chart-cell-text:#93a1a1; --chart-cell-text-hi:#fdf6e3;
  --chart-ocean-fill:#07303a; --chart-ocean-stroke:#155666;
  --chart-graticule:#155666; --chart-graticule-label:#586e75;
  --proto-tcp:#268bd2; --proto-udp:#b58900; --proto-icmp:#859900; --proto-l2:#6c71c4; --proto-default:#839496;
  --pcard-mode-banner:#859900; --pcard-mode-tarpit:#dc322f; --pcard-mode-drop:#586e75;
  --ctag-bg:#073642; --ctag-border:#155666; --ctag-text:#93a1a1;
  --ctag-tls-bg:#0a3848; --ctag-tls-border:#155666; --ctag-tls-fg:#268bd2;
  --help-badge-bg:#586e75; --help-badge-hover-bg:#268bd2;
  --widget-toggle-bg:#073642; --widget-toggle-fg:#839496; --widget-toggle-border:#155666;
  --palette-1:#268bd2; --palette-2:#cb4b16; --palette-3:#859900; --palette-4:#d33682; --palette-5:#dc322f;
  --palette-6:#2aa198; --palette-7:#b58900; --palette-8:#657b83; --palette-9:#6c71c4; --palette-10:#586e75;
  --ramp-0:#052731; --ramp-1:#073d4b; --ramp-2:#0a5168; --ramp-3:#106785; --ramp-4:#1a83a8; --ramp-5:#268bd2; --ramp-6:#5aa9e0;
  --heatmap-zero:#052731;
}
/* Nord — cool, slightly desaturated. */
:root.theme-nord {
  --bg-page:#2e3440; --bg-surface:#3b4252; --bg-elevated:#434c5e; --bg-code:#3b4252; --bg-code-block:#2e3440;
  --text:#d8dee9; --text-muted:#b0b8c5; --text-faint:#818896; --text-strong:#e5e9f0; --heading-h2:#d8dee9;
  --border:#434c5e; --border-medium:#4c566a; --border-strong:#4c566a;
  --link:#88c0d0; --link-hover-bg:#434c5e;
  --sev-low:#b0b8c5; --sev-medium:#ebcb8b; --sev-high:#d08770; --sev-critical:#bf616a; --sev-critical-bg:#3b2a30;
  --bar-default:#5e81ac; --bar-medium:#ebcb8b; --bar-high:#d08770; --bar-critical:#bf616a;
  --accent:#88c0d0; --accent-fg:#2e3440;
  --success-fg:#a3be8c; --success-bg:#303a2c; --success-border:#4e6048;
  --warning-fg:#ebcb8b; --warning-bg:#3a3528; --warning-border:#585030; --warning-text:#ebcb8b;
  --sortable-hover-bg:#434c5e; --arrow-faint:#5d6878;
  --tag-bg:#3b4252; --tag-border:#4c566a;
  --tag-warn-bg:#3a3528; --tag-warn-border:#585030;
  --tag-bad-bg:#3b2a30; --tag-bad-border:#58383c;
  --host-border:#4c566a; --svc-bg:#3b4252; --svc-border:#4c566a;
  --blockquote-bg:#3b4252;
  --counter-num:#eceff4;
  --chart-grid:#3b4252; --chart-axis-text:#b0b8c5; --chart-axis-text-faint:#818896;
  --chart-edge:#4c566a; --chart-node-default:#5e81ac; --chart-node-stroke:#2e3440;
  --chart-cell-text:#d8dee9; --chart-cell-text-hi:#eceff4;
  --chart-ocean-fill:#2e3440; --chart-ocean-stroke:#4c566a;
  --chart-graticule:#434c5e; --chart-graticule-label:#5d6878;
  --proto-tcp:#5e81ac; --proto-udp:#d08770; --proto-icmp:#a3be8c; --proto-l2:#b48ead; --proto-default:#b0b8c5;
  --pcard-mode-banner:#a3be8c; --pcard-mode-tarpit:#bf616a; --pcard-mode-drop:#4c566a;
  --ctag-bg:#3b4252; --ctag-border:#4c566a; --ctag-text:#d8dee9;
  --ctag-tls-bg:#3b4252; --ctag-tls-border:#4c566a; --ctag-tls-fg:#88c0d0;
  --help-badge-bg:#4c566a; --help-badge-hover-bg:#88c0d0;
  --widget-toggle-bg:#3b4252; --widget-toggle-fg:#b0b8c5; --widget-toggle-border:#4c566a;
  --palette-1:#5e81ac; --palette-2:#d08770; --palette-3:#a3be8c; --palette-4:#b48ead; --palette-5:#bf616a;
  --palette-6:#88c0d0; --palette-7:#ebcb8b; --palette-8:#b0b8c5; --palette-9:#81a1c1; --palette-10:#8fbcbb;
  --ramp-0:#2e3440; --ramp-1:#36404f; --ramp-2:#3e4d62; --ramp-3:#4a5d78; --ramp-4:#5e7595; --ramp-5:#88a0c0; --ramp-6:#aac0e0;
  --heatmap-zero:#2e3440;
}
/* High contrast — pure black bg, vivid accents, thick borders (accessibility). */
:root.theme-high-contrast {
  --bg-page:#000; --bg-surface:#0a0a0a; --bg-elevated:#181818; --bg-code:#0f0f0f; --bg-code-block:#0a0a0a;
  --text:#fff; --text-muted:#d0d0d0; --text-faint:#a0a0a0; --text-strong:#fff; --heading-h2:#fff;
  --border:#404040; --border-medium:#555; --border-strong:#707070;
  --link:#6ab0ff; --link-hover-bg:#1a1a1a;
  --sev-low:#d0d0d0; --sev-medium:#ffb000; --sev-high:#ff5050; --sev-critical:#ff2030; --sev-critical-bg:#2a0000;
  --bar-default:#6ab0ff; --bar-medium:#ffb000; --bar-high:#ff5050; --bar-critical:#ff2030;
  --accent:#6ab0ff; --accent-fg:#000;
  --success-fg:#00d060; --success-bg:#002a10; --success-border:#00803a;
  --warning-fg:#ffb000; --warning-bg:#2a1800; --warning-border:#806000; --warning-text:#ffb000;
  --sortable-hover-bg:#1a1a1a; --arrow-faint:#707070;
  --tag-bg:#181830; --tag-border:#3a3a55;
  --tag-warn-bg:#2a1800; --tag-warn-border:#806000;
  --tag-bad-bg:#2a0000; --tag-bad-border:#8a0010;
  --host-border:#707070; --svc-bg:#181830; --svc-border:#3a3a55;
  --blockquote-bg:#0f0f0f;
  --counter-num:#fff;
  --chart-grid:#2a2a2a; --chart-axis-text:#d0d0d0; --chart-axis-text-faint:#a0a0a0;
  --chart-edge:#707070; --chart-node-default:#6ab0ff; --chart-node-stroke:#000;
  --chart-cell-text:#fff; --chart-cell-text-hi:#fff;
  --chart-ocean-fill:#0a0a0a; --chart-ocean-stroke:#404040;
  --chart-graticule:#404040; --chart-graticule-label:#707070;
  --proto-tcp:#6ab0ff; --proto-udp:#ffb000; --proto-icmp:#00d060; --proto-l2:#ff70ff; --proto-default:#d0d0d0;
  --pcard-mode-banner:#00d060; --pcard-mode-tarpit:#ff2030; --pcard-mode-drop:#a0a0a0;
  --ctag-bg:#181818; --ctag-border:#404040; --ctag-text:#d0d0d0;
  --ctag-tls-bg:#00204a; --ctag-tls-border:#1a4080; --ctag-tls-fg:#6ab0ff;
  --help-badge-bg:#707070; --help-badge-hover-bg:#6ab0ff;
  --widget-toggle-bg:#181818; --widget-toggle-fg:#d0d0d0; --widget-toggle-border:#404040;
  --palette-1:#6ab0ff; --palette-2:#ffb000; --palette-3:#00d060; --palette-4:#ff70ff; --palette-5:#ff5050;
  --palette-6:#00e0e0; --palette-7:#ffe000; --palette-8:#d0d0d0; --palette-9:#b070ff; --palette-10:#70ff70;
  --ramp-0:#0a0a0a; --ramp-1:#102030; --ramp-2:#1a3855; --ramp-3:#205a85; --ramp-4:#3080c0; --ramp-5:#5aa0e0; --ramp-6:#80c0ff;
  --heatmap-zero:#0a0a0a;
}
/* Cobalt — saturated deep-blue dark theme. */
:root.theme-cobalt {
  --bg-page:#0a1929; --bg-surface:#102a42; --bg-elevated:#163455; --bg-code:#163455; --bg-code-block:#0d2237;
  --text:#e0eaf6; --text-muted:#92a8c0; --text-faint:#5a7090; --text-strong:#c8d6e8; --heading-h2:#b0c4dc;
  --border:#1e4068; --border-medium:#1e4068; --border-strong:#285178;
  --link:#2faaff; --link-hover-bg:#163455;
  --sev-low:#92a8c0; --sev-medium:#ffb648; --sev-high:#ff7088; --sev-critical:#ff4060; --sev-critical-bg:#3a1828;
  --bar-default:#2faaff; --bar-medium:#ffb648; --bar-high:#ff7088; --bar-critical:#ff4060;
  --accent:#2faaff; --accent-fg:#0a1929;
  --success-fg:#5ee090; --success-bg:#0a3020; --success-border:#1a5040;
  --warning-fg:#ffb648; --warning-bg:#3a2c0a; --warning-border:#5a4818; --warning-text:#ffb648;
  --sortable-hover-bg:#163455; --arrow-faint:#3a5878;
  --tag-bg:#163455; --tag-border:#285178;
  --tag-warn-bg:#3a2c0a; --tag-warn-border:#5a4818;
  --tag-bad-bg:#3a1828; --tag-bad-border:#5a2840;
  --host-border:#285178; --svc-bg:#163455; --svc-border:#285178;
  --blockquote-bg:#102a42;
  --counter-num:#e8f0fa;
  --chart-grid:#163455; --chart-axis-text:#92a8c0; --chart-axis-text-faint:#5a7090;
  --chart-edge:#285178; --chart-node-default:#2faaff; --chart-node-stroke:#0a1929;
  --chart-cell-text:#e0eaf6; --chart-cell-text-hi:#fff;
  --chart-ocean-fill:#0d2237; --chart-ocean-stroke:#285178;
  --chart-graticule:#163455; --chart-graticule-label:#3a5878;
  --proto-tcp:#2faaff; --proto-udp:#ffb648; --proto-icmp:#5ee090; --proto-l2:#a888ff; --proto-default:#92a8c0;
  --pcard-mode-banner:#5ee090; --pcard-mode-tarpit:#ff4060; --pcard-mode-drop:#5a7090;
  --ctag-bg:#163455; --ctag-border:#285178; --ctag-text:#b0c4dc;
  --ctag-tls-bg:#102a42; --ctag-tls-border:#1e4068; --ctag-tls-fg:#2faaff;
  --help-badge-bg:#3a5878; --help-badge-hover-bg:#2faaff;
  --widget-toggle-bg:#163455; --widget-toggle-fg:#92a8c0; --widget-toggle-border:#285178;
  --palette-1:#2faaff; --palette-2:#ffb648; --palette-3:#5ee090; --palette-4:#c878ff; --palette-5:#ff7088;
  --palette-6:#48d8e0; --palette-7:#e0d048; --palette-8:#92a8c0; --palette-9:#7088ff; --palette-10:#88d8a0;
  --ramp-0:#0a1929; --ramp-1:#0d2540; --ramp-2:#103358; --ramp-3:#184878; --ramp-4:#266aa8; --ramp-5:#3a92d0; --ramp-6:#5ab8f0;
  --heatmap-zero:#0a1929;
}
/* Sepia — warm parchment, light theme with brown accents. */
:root.theme-sepia {
  --bg-page:#f6efd9; --bg-surface:#fdf9eb; --bg-elevated:#f0e6c4; --bg-code:#ece1b8; --bg-code-block:#f3ead0;
  --text:#3a2818; --text-muted:#6a4f30; --text-faint:#8b7050; --text-strong:#2a1808; --heading-h2:#5a3a20;
  --border:#dccda0; --border-medium:#d8c890; --border-strong:#c4b080;
  --link:#8b5a2b; --link-hover-bg:#f0e6c4;
  --sev-low:#6a4f30; --sev-medium:#a8590a; --sev-high:#8b1a1a; --sev-critical:#6b0000; --sev-critical-bg:#f4d0c0;
  --bar-default:#8b5a2b; --bar-medium:#c08020; --bar-high:#a83020; --bar-critical:#7a1010;
  --accent:#8b5a2b; --accent-fg:#fdf9eb;
  --success-fg:#506830; --success-bg:#e0e8c8; --success-border:#a8b078;
  --warning-fg:#8c5818; --warning-bg:#f4e0a8; --warning-border:#d8b860; --warning-text:#a8590a;
  --sortable-hover-bg:#ede0b8; --arrow-faint:#c4a878;
  --tag-bg:#f0e0b0; --tag-border:#d4c080;
  --tag-warn-bg:#f4e0a8; --tag-warn-border:#d8b860;
  --tag-bad-bg:#f4d0c0; --tag-bad-border:#d49080;
  --host-border:#c4b080; --svc-bg:#f0e0b0; --svc-border:#d4c080;
  --blockquote-bg:#f0e6c4;
  --counter-num:#3a2818;
  --chart-grid:#ece1b8; --chart-axis-text:#6a4f30; --chart-axis-text-faint:#8b7050;
  --chart-edge:#c4b080; --chart-node-default:#8b5a2b; --chart-node-stroke:#fdf9eb;
  --chart-cell-text:#3a2818; --chart-cell-text-hi:#fdf9eb;
  --chart-ocean-fill:#f0e6c4; --chart-ocean-stroke:#d8c890;
  --chart-graticule:#dccda0; --chart-graticule-label:#a89070;
  --proto-tcp:#8b5a2b; --proto-udp:#c08020; --proto-icmp:#5a7820; --proto-l2:#7a5040; --proto-default:#8b7050;
  --pcard-mode-banner:#5a7820; --pcard-mode-tarpit:#a83020; --pcard-mode-drop:#a89070;
  --ctag-bg:#ece1b8; --ctag-border:#d4c080; --ctag-text:#6a4f30;
  --ctag-tls-bg:#e8d8b0; --ctag-tls-border:#c4a878; --ctag-tls-fg:#8b5a2b;
  --help-badge-bg:#a89070; --help-badge-hover-bg:#8b5a2b;
  --widget-toggle-bg:#f0e0b0; --widget-toggle-fg:#6a4f30; --widget-toggle-border:#d4c080;
  --palette-1:#8b5a2b; --palette-2:#a8590a; --palette-3:#5a7820; --palette-4:#7a4068; --palette-5:#a83020;
  --palette-6:#386870; --palette-7:#9b8020; --palette-8:#8b7050; --palette-9:#6a4090; --palette-10:#506030;
  --ramp-0:#fdf9eb; --ramp-1:#f0e0b0; --ramp-2:#e8c878; --ramp-3:#d8a848; --ramp-4:#b88030; --ramp-5:#8b5a2b; --ramp-6:#5a3818;
  --heatmap-zero:#fdf9eb;
}
/* Olive — desaturated olive drab; medium-dark green-brown surfaces. */
:root.theme-olive {
  --bg-page:#3a402a; --bg-surface:#494e36; --bg-elevated:#535938; --bg-code:#535938; --bg-code-block:#2f3522;
  --text:#e0e5b8; --text-muted:#b0b890; --text-faint:#8a9068; --text-strong:#ecf0c8; --heading-h2:#c8d098;
  --border:#5a6038; --border-medium:#5a6038; --border-strong:#6a7048;
  --link:#cad860; --link-hover-bg:#535938;
  --sev-low:#b0b890; --sev-medium:#e0b048; --sev-high:#e07050; --sev-critical:#d04030; --sev-critical-bg:#4a2818;
  --bar-default:#a8b855; --bar-medium:#e0b048; --bar-high:#e07050; --bar-critical:#d04030;
  --accent:#cad860; --accent-fg:#2c321e;
  --success-fg:#9bc060; --success-bg:#2a3a18; --success-border:#4a5e28;
  --warning-fg:#e0b048; --warning-bg:#3a2e10; --warning-border:#5a4820; --warning-text:#e0b048;
  --sortable-hover-bg:#535938; --arrow-faint:#7a8050;
  --tag-bg:#535938; --tag-border:#6a7048;
  --tag-warn-bg:#3a2e10; --tag-warn-border:#5a4820;
  --tag-bad-bg:#4a2818; --tag-bad-border:#6a3818;
  --host-border:#6a7048; --svc-bg:#535938; --svc-border:#6a7048;
  --blockquote-bg:#494e36;
  --counter-num:#ecf0c8;
  --chart-grid:#535938; --chart-axis-text:#b0b890; --chart-axis-text-faint:#8a9068;
  --chart-edge:#6a7048; --chart-node-default:#a8b855; --chart-node-stroke:#3a402a;
  --chart-cell-text:#e0e5b8; --chart-cell-text-hi:#fff;
  --chart-ocean-fill:#2f3522; --chart-ocean-stroke:#5a6038;
  --chart-graticule:#535938; --chart-graticule-label:#7a8050;
  --proto-tcp:#88a868; --proto-udp:#e0b048; --proto-icmp:#9bc060; --proto-l2:#b88aa0; --proto-default:#b0b890;
  --pcard-mode-banner:#9bc060; --pcard-mode-tarpit:#d04030; --pcard-mode-drop:#8a9068;
  --ctag-bg:#535938; --ctag-border:#6a7048; --ctag-text:#c8d098;
  --ctag-tls-bg:#4a5e28; --ctag-tls-border:#6a8038; --ctag-tls-fg:#cad860;
  --help-badge-bg:#7a8050; --help-badge-hover-bg:#cad860;
  --widget-toggle-bg:#535938; --widget-toggle-fg:#b0b890; --widget-toggle-border:#6a7048;
  --palette-1:#a8b855; --palette-2:#e0b048; --palette-3:#9bc060; --palette-4:#b88aa0; --palette-5:#e07050;
  --palette-6:#78a8a8; --palette-7:#e0c060; --palette-8:#b0b890; --palette-9:#a098c8; --palette-10:#88a868;
  --ramp-0:#2f3522; --ramp-1:#3a402a; --ramp-2:#4a5028; --ramp-3:#6a7040; --ramp-4:#8a9858; --ramp-5:#a8b870; --ramp-6:#cad898;
  --heatmap-zero:#2f3522;
}
/* ---- Size scale: applied to :root so every rem-based size inherits. ---- */
:root.size-small   { --font-size-base:12px; }
:root.size-large   { --font-size-base:16px; }
:root.size-xlarge  { --font-size-base:18px; }
:root.size-xxlarge { --font-size-base:20px; }
html { font-size: var(--font-size-base); }
/* ---- Core element styles (every color comes from a variable above). ---- */
body { font: 1rem/1.45 ui-monospace, "SF Mono", Menlo, Consolas, monospace; margin: 1.5rem; color: var(--text); background: var(--bg-page); }
h1 { font-size: 1.3rem; margin: 0 0 1rem; }
h2 { font-size: 1.05rem; margin: 1.5rem 0 .5rem; color: var(--heading-h2); }
nav { margin-bottom: 1rem; }
nav a { margin-right: 1rem; color: var(--link); }
a { color: var(--link); }
table { border-collapse: collapse; width: 100%; background: var(--bg-surface); }
th, td { padding: .35rem .55rem; border-bottom: 1px solid var(--border); text-align: left; vertical-align: top; }
th { font-weight: 600; background: var(--bg-elevated); color: var(--text); }
td.sev-low { color: var(--sev-low); }
td.sev-medium { color: var(--sev-medium); }
td.sev-high { color: var(--sev-high); font-weight: 600; }
td.sev-critical { color: var(--sev-critical); font-weight: 700; background: var(--sev-critical-bg); }
form { display: inline-block; }
input[type=text], input[type=number] { font: inherit; padding: .15rem .3rem; background: var(--bg-surface); color: var(--text); border: 1px solid var(--border-medium); }
.kv { background: var(--bg-surface); padding: .75rem; border: 1px solid var(--border); white-space: pre-wrap; word-break: break-all; color: var(--text); }
.note { color: var(--text-muted); font-size: 0.857rem; margin-top: .5rem; }
.net { background: var(--bg-surface); border: 1px solid var(--border-medium); border-radius: 4px; padding: .6rem .8rem; margin: .6rem 0; }
.net h3 { margin: 0 0 .35rem; font-size: 1rem; }
.net .meta { color: var(--text-muted); font-size: 0.857rem; margin-bottom: .4rem; }
.host { border-left: 3px solid var(--host-border); padding: .15rem 0 .15rem .6rem; margin: .35rem 0; }
.host .hostline { font-weight: 600; }
.host .os { color: var(--text-faint); font-weight: 400; }
.svc { display: inline-block; background: var(--svc-bg); border: 1px solid var(--svc-border); border-radius: 3px; padding: 0 .35rem; margin: .1rem .25rem .1rem 0; font-size: 0.857rem; color: var(--text); }
.docs h2 { border-bottom: 1px solid var(--border); padding-bottom: .2rem; }
.docs code { background: var(--bg-code); padding: 0 .25rem; border-radius: 3px; color: var(--text); }
.docs ul { margin: .3rem 0 .8rem 1.2rem; padding: 0; }
.docs li { margin: .12rem 0; }
.doclib { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: .5rem; margin: .5rem 0 1rem; }
.doccard { display: block; background: var(--bg-surface); border: 1px solid var(--border-medium); border-left: 4px solid var(--accent); border-radius: 4px; padding: .45rem .6rem; text-decoration: none; color: var(--link); }
.doccard:hover { border-left-color: var(--link); background: var(--link-hover-bg); }
.doccard b { display: block; }
.doccard span { display: block; color: var(--text-muted); font-size: 0.857rem; margin-top: .15rem; }
.mddoc { max-width: 60rem; }
.mddoc h1 { font-size: 1.4rem; margin: .3rem 0 1rem; }
.mddoc h2 { font-size: 1.1rem; }
.mddoc h3 { font-size: 1rem; color: var(--heading-h2); margin: 1rem 0 .35rem; }
.mddoc p { margin: .5rem 0; }
.mddoc code { background: var(--bg-code); padding: 0 .25rem; border-radius: 3px; color: var(--text); }
.mddoc pre { background: var(--bg-code-block); border: 1px solid var(--border-medium); border-radius: 4px; padding: .6rem .8rem; overflow-x: auto; color: var(--text); }
.mddoc pre code { background: none; padding: 0; }
.mddoc table { margin: .6rem 0; }
.mddoc blockquote { margin: .6rem 0; padding: .3rem .8rem; border-left: 3px solid var(--host-border); background: var(--blockquote-bg); color: var(--heading-h2); }
.mddoc hr { border: none; border-top: 1px solid var(--border-medium); margin: 1.2rem 0; }
.mddoc .docnav { margin-bottom: .8rem; }
.depl { background: var(--bg-surface); border: 1px solid var(--border-medium); border-radius: 4px; padding: .5rem .8rem; display: inline-block; }
.threat-low { color: var(--sev-low); }
.threat-elevated { color: var(--sev-medium); font-weight: 600; }
.threat-high { color: var(--sev-high); font-weight: 600; }
.threat-critical { color: var(--sev-critical); font-weight: 700; background: var(--sev-critical-bg); }
.tag { display: inline-block; background: var(--tag-bg); border: 1px solid var(--tag-border); border-radius: 3px; padding: 0 .35rem; margin: .1rem .2rem .1rem 0; font-size: 0.857rem; color: var(--text); }
.tag.warn { background: var(--tag-warn-bg); border-color: var(--tag-warn-border); }
.tag.bad { background: var(--tag-bad-bg); border-color: var(--tag-bad-border); }
table.chart { width: 100%; background: transparent; }
table.chart td { border: none; padding: .12rem .4rem; }
td.blabel { width: 32%; max-width: 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
td.bcell { width: 58%; }
td.bnum { width: 10%; text-align: right; color: var(--text-muted); }
.bar { display: inline-block; height: .8rem; background: var(--bar-default); border-radius: 2px; min-width: 2px; }
.bar.sev-medium { background: var(--bar-medium); }
.bar.sev-high { background: var(--bar-high); }
.bar.sev-critical { background: var(--bar-critical); }
.spark { display: flex; align-items: flex-end; gap: 1px; height: 80px; background: var(--bg-surface); border: 1px solid var(--border); padding: 4px; }
.sparkbar { flex: 1 1 0; background: var(--bar-default); min-height: 1px; }
#live-pill { display: inline-block; margin-left: .5rem; padding: 0 .5rem; border-radius: 10px; background: var(--success-bg); border: 1px solid var(--success-border); color: var(--success-fg); font-size: 0.857rem; font-weight: 600; }
#live-pill button { font: inherit; cursor: pointer; border: 1px solid var(--success-border); background: var(--bg-surface); border-radius: 3px; padding: 0 .35rem; margin-left: .35rem; color: var(--success-fg); }
th.sortable { cursor: pointer; }
th.sortable:hover { background: var(--sortable-hover-bg); }
th.sortable:not([data-arrow])::after { content: " \2195"; color: var(--arrow-faint); font-weight: 400; }
th[data-arrow]::after { content: " " attr(data-arrow); color: var(--success-fg); font-weight: 400; }
input.tablefilter { margin: .3rem 0; padding: .15rem .35rem; font: inherit; width: 16rem; max-width: 100%; background: var(--bg-surface); color: var(--text); border: 1px solid var(--border-medium); }
.nojs-note { color: var(--warning-text); font-size: 0.857rem; }
html.js .nojs-note { display: none; }
.canvas-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(132px, 1fr)); gap: .5rem; margin: .5rem 0 1rem; }
.pcard { background: var(--bg-surface); border: 1px solid var(--border-medium); border-left: 4px solid var(--bar-default); border-radius: 4px; padding: .4rem .55rem; }
.pcard.mode-tarpit { border-left-color: var(--pcard-mode-tarpit); }
.pcard.mode-drop { border-left-color: var(--pcard-mode-drop); }
.pcard.mode-banner { border-left-color: var(--pcard-mode-banner); }
.pcard-top { display: flex; align-items: baseline; justify-content: space-between; }
.pcard-port { font-size: 1.15rem; font-weight: 700; color: var(--text); }
.pcard-svc { font-weight: 600; color: var(--text-strong); margin-top: .1rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.pcard-meta { color: var(--text-faint); font-size: 0.786rem; margin: .05rem 0 .25rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.proto { font-size: 0.714rem; font-weight: 700; text-transform: uppercase; padding: 0 .3rem; border-radius: 3px; color: #fff; background: var(--proto-default); }
.proto-tcp { background: var(--proto-tcp); }
.proto-udp { background: var(--proto-udp); }
.proto-icmp { background: var(--proto-icmp); }
.proto-l2 { background: var(--proto-l2); }
.ovr { display: inline-block; background: var(--warning-bg); border: 1px solid var(--warning-border); color: var(--warning-fg); border-radius: 3px; padding: 0 .35rem; font-size: 0.786rem; font-weight: 600; cursor: help; }
.ctag { display: inline-block; background: var(--ctag-bg); border: 1px solid var(--ctag-border); border-radius: 3px; padding: 0 .3rem; margin: .1rem .2rem 0 0; font-size: 0.714rem; color: var(--ctag-text); }
.ctag.tls { background: var(--ctag-tls-bg); border-color: var(--ctag-tls-border); color: var(--ctag-tls-fg); }
.ctag.cap { background: var(--warning-bg); border-color: var(--warning-border); color: var(--warning-fg); }
.coll-group { margin: .35rem 0; }
.coll-cat { display: inline-block; width: 9rem; color: var(--text-muted); font-size: 0.857rem; vertical-align: top; }
.coll { display: inline-block; border-radius: 10px; padding: .05rem .5rem; margin: .12rem .2rem; font-size: 0.857rem; border: 1px solid var(--border-strong); background: var(--bg-elevated); color: var(--text-faint); }
.coll.on { background: var(--success-bg); border-color: var(--success-border); color: var(--success-fg); font-weight: 600; }
.coll.off { background: var(--bg-elevated); border-color: var(--border-strong); color: var(--text-faint); }
.coll-detail { color: var(--success-fg); font-weight: 400; font-size: 0.786rem; }
.counters { display: flex; flex-wrap: wrap; gap: .5rem; margin: .5rem 0; }
.counter { min-width: 6rem; background: var(--bg-surface); border: 1px solid var(--border-medium); border-radius: 6px; padding: .35rem .6rem; text-align: center; }
.counter b { display: block; font-size: 1.43rem; line-height: 1.1; color: var(--counter-num); }
.counter span { font-size: 0.786rem; color: var(--text-faint); text-transform: uppercase; letter-spacing: .03em; }
.counter-cat { align-self: center; width: 6.5rem; color: var(--text-muted); font-size: 0.857rem; }
svg.graph { background: var(--bg-surface); border: 1px solid var(--border); border-radius: 4px; }
svg.graph .edge { stroke: var(--chart-edge); stroke-width: 1; }
svg.graph .node { fill: var(--chart-node-default); }
svg.graph .nlabel { font: 0.786rem ui-monospace, monospace; fill: var(--text-strong); }
figure[data-chart], .tc-fig { margin: .4rem 0 1rem; background: var(--bg-surface); border: 1px solid var(--border); border-radius: 4px; padding: .5rem .6rem; overflow-x: auto; }
.charts-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(330px, 1fr)); gap: .8rem; align-items: start; }
figcaption.tc-cap, .tc-cap { font-weight: 600; color: var(--heading-h2); margin-bottom: .3rem; font-size: .95rem; }
svg.tc { background: var(--bg-surface); max-width: 100%; height: auto; }
svg.tc text { font: 0.786rem ui-monospace, monospace; }
.tc-grid { stroke: var(--chart-grid); stroke-width: 1; }
.tc-lane { stroke: var(--chart-grid); stroke-width: 1; stroke-dasharray: 2 3; }
.tc-ax { fill: var(--chart-axis-text-faint); }
.tc-axt { fill: var(--chart-axis-text); font-weight: 600; text-anchor: middle; }
.tc-val { fill: var(--chart-axis-text); }
.tc-barrect:hover, .tc-slice:hover, .tc-cell:hover, .tc-pt:hover, .tc-src:hover { opacity: .82; }
.tc-slice { stroke: var(--chart-node-stroke); stroke-width: 1; }
.tc-pt { stroke: var(--chart-node-stroke); stroke-width: .5; }
.tc-pl { stroke-linejoin: round; stroke-linecap: round; }
.tc-cellv { fill: var(--chart-cell-text); font-size: 0.714rem; }
.tc-cellv.hi { fill: var(--chart-cell-text-hi); }
.tc-node { stroke: var(--chart-node-stroke); stroke-width: 1.2; fill: var(--chart-node-default); }
.tc-node.k-gateway { fill: var(--proto-udp); }
.tc-node.k-resolver { fill: var(--proto-icmp); }
.tc-node.k-attacker { fill: var(--sev-critical); }
.tc-nlabel { font: 0.714rem ui-monospace, monospace; fill: var(--text-strong); }
.tc-grouphdr { fill: var(--text-faint); font-weight: 700; font-size: 0.786rem; }
.tc-edge { stroke: var(--chart-edge); stroke-width: 1.2; }
.tc-snode { stroke: var(--chart-node-stroke); }
.tc-tev { stroke: var(--chart-node-stroke); stroke-width: 1; }
.tc-ocean { fill: var(--chart-ocean-fill); stroke: var(--chart-ocean-stroke); }
.tc-grat { stroke: var(--chart-graticule); stroke-width: 1; }
.tc-grat-lbl { fill: var(--chart-graticule-label); font-size: 0.64rem; }
.tc-src { stroke-width: 1; }
.tc-legend { margin-top: .35rem; font-size: 0.786rem; color: var(--text-muted); }
.tc-leg { margin-right: .8rem; white-space: nowrap; }
.tc-sw { display: inline-block; width: 10px; height: 10px; border-radius: 2px; vertical-align: middle; }
.tc-replay { background: var(--chart-replay-bg); color: var(--chart-replay-text); font: 0.857rem ui-monospace, monospace; border-radius: 4px; padding: .5rem .6rem; max-height: 340px; overflow: auto; }
.tc-rline { white-space: pre-wrap; word-break: break-all; padding: .05rem 0; }
.tc-rline.dir-out { color: var(--chart-replay-stale); }
.tc-rts { color: var(--chart-replay-ts); margin-right: .6rem; }
.tc-zoomable { cursor: zoom-in; }
figure.tc-zoom { position: fixed; inset: 3vh 3vw; z-index: 1000; margin: 0; overflow: auto; cursor: zoom-out; box-shadow: 0 0 0 100vmax rgba(20,24,33,.5); }
figure.tc-zoom svg.tc { max-height: 90vh; width: 100%; }
.widget-toggle { float: right; font: inherit; font-size: 0.786rem; cursor: pointer; border: 1px solid var(--widget-toggle-border); background: var(--widget-toggle-bg); border-radius: 3px; padding: 0 .4rem; color: var(--widget-toggle-fg); }
figure.widget-hidden { padding-bottom: .35rem; }
figure.widget-hidden svg, figure.widget-hidden .tc-legend, figure.widget-hidden .tc-replay, figure.widget-hidden table, figure.widget-hidden .note, figure.widget-hidden p { display: none; }
.help { display: inline-block; width: 14px; height: 14px; line-height: 14px; text-align: center; font-size: 0.714rem; font-weight: 700; color: #fff; background: var(--help-badge-bg); border-radius: 50%; cursor: help; vertical-align: middle; }
.help:hover, .help:focus { background: var(--help-badge-hover-bg); outline: none; }
/* Theme picker (config page) */
.theme-picker { display: flex; flex-wrap: wrap; gap: .4rem; margin: .3rem 0 1rem; }
.theme-picker a.themelink { display: inline-block; padding: .25rem .65rem; border-radius: 4px; border: 1px solid var(--border-medium); background: var(--bg-surface); color: var(--text); text-decoration: none; font-size: 0.93rem; }
.theme-picker a.themelink:hover { border-color: var(--accent); }
.theme-picker a.themelink.active { background: var(--accent); border-color: var(--accent); color: var(--accent-fg); font-weight: 600; }
.theme-picker .swatch { display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: .35rem; vertical-align: middle; border: 1px solid var(--border-strong); }
</style>
<script src="/static/app.js" defer></script>
<script src="/static/charts.js" defer></script>
</head><body>
<nav><a href="/">summary</a> · <a href="/events">events</a> · <a href="/search">search</a> · <a href="/timeline">timeline</a> · <a href="/attack">att&amp;ck</a> · <a href="/correlation">correlation</a> · <a href="/fleet">fleet</a> · <a href="/iocs">iocs</a> · <a href="/tunnels">tunnels</a> · <a href="/profiles">profiles</a> · <a href="/fingerprints">fingerprints</a> · <a href="/devices">devices</a> · <a href="/topology">topology</a> · <a href="/charts">charts</a> · <a href="/health">health</a> · <a href="/alerting">alerting</a> · <a href="/errors">errors</a> · <a href="/config">config</a> · <a href="/docs">docs</a></nav>
{{ end }}

{{ define "foot" }}<p class="note">read-only view · {{ if gt (refreshSeconds) 0 }}auto-refreshes every {{ refreshSeconds }}s{{ else }}refresh for latest{{ end }} · <span class="nojs-note">JavaScript off — using &lt;meta refresh&gt; fallback; enable JS for the live pill, sortable tables &amp; graphs</span></p></body></html>{{ end }}

{{ define "bars" }}<table class="chart">
{{ range . }}<tr>
  <td class="blabel">{{ if .Href }}<a href="{{ .Href }}">{{ .Label }}</a>{{ else }}{{ .Label }}{{ end }}</td>
  <td class="bcell"><span class="bar {{ .Class }}" style="width:{{ .Pct }}%">&nbsp;</span></td>
  <td class="bnum">{{ .Count }}</td>
</tr>{{ end }}
</table>{{ end }}

{{ define "chartfig" }}<figure data-chart="{{ .Type }}"{{ if .Title }} data-chart-title="{{ .Title }}"{{ end }} data-chart-b64="{{ .B64 }}"><p class="note">enable JavaScript to render this chart</p></figure>{{ end }}

{{ define "charts" }}{{ template "head" . }}
<h1 data-help="Charts are rendered client-side by the packaged charts.js. Click a chart to zoom it (Esc or click again to restore); use each chart's hide/show button to curate the page — the choice is remembered in your browser.">analytics</h1>
{{ if .Empty }}<p class="note">No data yet — charts populate as the sensor records events. JSON sources at <a href="/api/summary">/api/summary</a> and <a href="/api/topology">/api/topology</a>.</p>{{ end }}
{{ range .Sections }}<h2>{{ .Heading }}</h2>
<div class="charts-grid">{{ range .Figs }}{{ template "chartfig" . }}{{ end }}</div>
{{ end }}
<p class="note">All charts are rendered client-side by the packaged charts.js (no external libraries) · derived from a scan of {{ .Scanned }} recent events. With JavaScript off, each figure shows a fallback note.</p>
{{ template "foot" . }}{{ end }}

{{ define "index" }}{{ template "head" . }}
<h1>tarpit-honeypot — last 24 hours</h1>
<p>{{ .Sum.Total }} events since {{ fmtTime .Sum.Since }}</p>

<div class="counters">{{ range .Counters }}<span class="counter"><b>{{ .Value }}</b><span>{{ .Label }}</span></span>{{ end }}</div>
{{ if .HasFrames }}
<div class="counters"><span class="counter-cat">L2 frames (sniffer)</span>{{ range .Frames }}<span class="counter"><b>{{ .Value }}</b><span>{{ .Label }}</span></span>{{ end }}</div>
{{ else }}<p class="note">L2 packet counters appear here when the AF_PACKET sniffer is enabled (<code>sniffer.enabled</code>, needs CAP_NET_RAW).</p>{{ end }}

<h2>events per hour</h2>
{{ if .Trend }}<div class="spark">{{ range .Trend }}<span class="sparkbar" style="height:{{ .Pct }}%" title="{{ .Label }}: {{ .Count }}">&nbsp;</span>{{ end }}</div>
<p class="note">last 24h, one bar per hour</p>{{ else }}<p class="note">no events yet</p>{{ end }}

{{ if .Charts }}<h2>visual overview</h2>
<div class="charts-grid">{{ range .Charts }}{{ template "chartfig" . }}{{ end }}</div>
<p class="note">Full interactive analytics — bar / pie / heatmap / source map / credential / timeline — at <a href="/charts">charts</a>.</p>{{ end }}

<h2>by severity</h2>
{{ if .Severity }}{{ template "bars" .Severity }}{{ else }}<p class="note">none</p>{{ end }}

<h2>top rules</h2>
{{ if .Rules }}{{ template "bars" .Rules }}{{ else }}<p class="note">none</p>{{ end }}

<h2>top sources</h2>
{{ if .Sources }}{{ template "bars" .Sources }}{{ else }}<p class="note">none</p>{{ end }}
<p class="note">Source IPs link to their <a href="/profiles">attacker profile</a>.</p>

<h2>by ATT&amp;CK tactic</h2>
{{ if .Tactics }}{{ template "bars" .Tactics }}<p class="note">Full kill-chain view at <a href="/attack">att&amp;ck</a>.</p>{{ else }}<p class="note">none</p>{{ end }}

<h2>by handler</h2>
{{ if .Handlers }}{{ template "bars" .Handlers }}{{ else }}<p class="note">none</p>{{ end }}

<h2>top source countries</h2>
{{ if .Countries }}{{ template "bars" .Countries }}{{ else }}<p class="note">no geo enrichment (set sensor.geoip)</p>{{ end }}

<h2>top source ASNs</h2>
{{ if .ASNs }}{{ template "bars" .ASNs }}{{ else }}<p class="note">no ASN enrichment</p>{{ end }}

<h2>top tools / scanners</h2>
{{ if .Tools }}{{ template "bars" .Tools }}{{ else }}<p class="note">none identified</p>{{ end }}
{{ if .Scanned }}<p class="note">tactic / geo / ASN / tool / handler charts from a scan of {{ .Scanned }} recent events.</p>{{ end }}
{{ template "foot" . }}{{ end }}

{{ define "attack" }}{{ template "head" . }}
<h1>ATT&amp;CK mapping — last 24 hours</h1>
<p>{{ .Events }} attributed events · {{ .DistinctTID }} distinct techniques across {{ len .Tactics }} tactics.</p>
<p class="note">Recomputed live from each event's rule + handler + anomaly markers (the same mapping the router stamps); see <a href="/docs">docs</a> for the catalog.</p>

<h2>tactic timeline (kill-chain order)</h2>
{{ if .Tactics }}{{ range .Tactics }}
<div class="net">
  <h3>{{ .Rank }}. {{ .Tactic }} <span class="meta">{{ .Count }} events</span></h3>
  <table class="chart"><tr><td class="bcell"><span class="bar" style="width:{{ .Pct }}%">&nbsp;</span></td><td class="bnum">{{ .Count }}</td></tr></table>
  {{ if .Techniques }}{{ template "bars" .Techniques }}{{ end }}
</div>{{ end }}{{ else }}<p class="note">no ATT&amp;CK-attributed events in the window yet</p>{{ end }}

<h2>technique heatmap (top 25 by volume)</h2>
{{ if .TopTech }}{{ template "bars" .TopTech }}{{ else }}<p class="note">none</p>{{ end }}

<h2>recent kill-chain progressions</h2>
{{ if .Chains }}<table><tr><th>time</th><th>source</th><th>chain</th></tr>
{{ range .Chains }}<tr><td>{{ fmtTime .Time }}</td><td>{{ if .Source }}<a href="/profiles/{{ .Source }}">{{ .Source }}</a>{{ end }}</td><td>{{ .Chain }}</td></tr>{{ end }}
</table>{{ else }}<p class="note">no multi-stage storylines yet (storyline:multi_stage fires when one source touches 3+ tactics in 30m)</p>{{ end }}
<p class="note">JSON at <a href="/api/attack">/api/attack</a>. Click a technique to see what it means and which sources triggered it.</p>
{{ template "foot" . }}{{ end }}

{{ define "technique" }}{{ template "head" . }}
<h1>ATT&amp;CK technique — {{ .ID }}</h1>
<p><a href="https://attack.mitre.org/techniques/{{ .ID }}/" rel="noreferrer noopener">{{ .ID }} on attack.mitre.org</a> · <a href="/attack">&larr; all techniques</a></p>
{{ if .Description }}<div class="depl">{{ .Description }}</div>{{ else }}<p class="note">No local description for this technique.</p>{{ end }}
<p>{{ .Events }} event(s) in the last 24h carried this technique{{ if .Tactics }} · tactic(s): {{ range .Tactics }}<span class="tag">{{ . }}</span>{{ end }}{{ end }}.</p>
<h2>sources that triggered it</h2>
{{ if .Sources }}{{ template "bars" .Sources }}<p class="note">Source IPs link to their attacker profile.</p>{{ else }}<p class="note">none in the window</p>{{ end }}
<h2>rules that mapped to it</h2>
{{ if .Rules }}{{ template "bars" .Rules }}{{ else }}<p class="note">none</p>{{ end }}
{{ template "foot" . }}{{ end }}

{{ define "timeline" }}{{ template "head" . }}
<h1>attack timeline — last 24 hours</h1>
<p class="note">Per-source event sequences (top {{ len .Sources }} sources by volume), time-ordered, so you can read each attacker's progression. Severity colors the rule; chips are the ATT&amp;CK tactics touched.</p>
{{ if .Sources }}{{ range .Sources }}
<div class="net">
  <h3><a href="/profiles/{{ .Source }}">{{ .Source }}</a> <span class="meta">{{ .Count }} events · {{ fmtTime .FirstSeen }} → {{ fmtTime .LastSeen }}</span></h3>
  <div class="meta">tactics: {{ if .Tactics }}{{ range .Tactics }}<span class="tag">{{ . }}</span>{{ end }}{{ else }}—{{ end }}</div>
  <table>
  {{ range .Events }}<tr>
    <td style="white-space:nowrap">{{ fmtTime .Time }}</td>
    <td class="sev-{{ .Severity }}">{{ .RuleID }}</td>
    <td>{{ .Handler }}{{ if .Port }}:{{ .Port }}{{ end }}</td>
    <td>{{ range .Tactics }}<span class="tag">{{ . }}</span>{{ end }}</td>
  </tr>{{ end }}
  </table>
  {{ if gt .Truncated 0 }}<p class="note">… {{ .Truncated }} earlier event(s) not shown — <a href="/events?source={{ .Source }}">see all</a></p>{{ end }}
</div>{{ end }}{{ else }}<p class="note">no events in the window yet</p>{{ end }}
{{ template "foot" . }}{{ end }}

{{ define "correlation" }}{{ template "head" . }}
<h1>correlation — last 24 hours</h1>
<p class="note">Per-source pivot chains: IP → fingerprints → User-Agents → ASN/country → domains → tools → credentials → malware → sessions. Chips link to the relevant view.</p>
{{ if .GraphB64 }}<div id="corrgraph" data-graph-b64="{{ .GraphB64 }}"><p class="note">enable JavaScript to render the interactive pivot graph</p></div>{{ end }}
{{ if .Sources }}{{ range .Sources }}
<div class="net">
  <h3 class="sev-{{ .MaxSev }}"><a href="/profiles/{{ .IP }}">{{ .IP }}</a> <span class="meta">{{ .Count }} events</span></h3>
  <table>
    {{ if .FPs }}<tr><th>fingerprints</th><td>{{ range .FPs }}<a class="tag" href="/fingerprints/{{ .Kind }}/{{ .Value }}">{{ .Kind }}:{{ .Value }}</a> {{ end }}</td></tr>{{ end }}
    {{ if .UAs }}<tr><th>user-agents</th><td>{{ range .UAs }}<span class="tag">{{ . }}</span> {{ end }}</td></tr>{{ end }}
    {{ if .ASN }}<tr><th>asn</th><td>{{ .ASN }}{{ if .Countries }} · {{ range .Countries }}<span class="tag">{{ . }}</span> {{ end }}{{ end }}</td></tr>{{ end }}
    {{ if .Domains }}<tr><th>domains</th><td>{{ range .Domains }}<span class="tag">{{ . }}</span> {{ end }}</td></tr>{{ end }}
    {{ if .Tools }}<tr><th>tools</th><td>{{ range .Tools }}<span class="tag warn">{{ . }}</span> {{ end }}</td></tr>{{ end }}
    {{ if .Creds }}<tr><th>credentials</th><td>{{ range .Creds }}<span class="tag bad">{{ . }}</span> {{ end }}</td></tr>{{ end }}
    {{ if .Malware }}<tr><th>malware</th><td>{{ range .Malware }}<span class="tag bad">{{ . }}</span> {{ end }}</td></tr>{{ end }}
    {{ if .Tactics }}<tr><th>tactics</th><td>{{ range .Tactics }}<span class="tag">{{ . }}</span> {{ end }}</td></tr>{{ end }}
    {{ if .Sessions }}<tr><th>sessions</th><td>{{ .Sessions }} recorded · <a href="/events?source={{ .IP }}">events</a></td></tr>{{ end }}
  </table>
</div>{{ end }}{{ else }}<p class="note">no events in the window yet</p>{{ end }}
{{ template "foot" . }}{{ end }}

{{ define "fleet" }}{{ template "head" . }}
<h1>fleet correlation</h1>
<p class="note">Cross-sensor findings — patterns no single honeypot can see: one
source / ASN / fingerprint / payload / credential / CVE / tool / port / technique
hitting many sensors, shared C2, novel infrastructure, persistent networks, and
more. Runs on an aggregator with <code>ingest:</code> enabled. JSON at
<a href="/api/fleet">/api/fleet</a>.</p>
<form method="get" action="/fleet">
  since: <input type="text" name="since" value="{{ .SinceStr }}" placeholder="24h" size="6">
  <button type="submit">filter</button>
  <a href="/fleet">reset</a>
</form>
{{ if not .Findings }}
<p class="note">No fleet correlations in the window. (Cross-sensor detection needs
an aggregator receiving events from several sensors via <code>ingest:</code>.)</p>
{{ else }}
<h2>detectors fired</h2>
<p class="note">Each bar links to the matching events.</p>
{{ template "bars" .Counts }}
<h2>findings over time</h2>
{{ if .Timeline }}{{ template "bars" .Timeline }}{{ else }}<p class="note">—</p>{{ end }}
<h2>findings ({{ .Total }})</h2>
<table>
  <tr><th>time (utc)</th><th>severity</th><th>detector</th><th>summary</th><th></th></tr>
  {{ range .Findings }}
  <tr>
    <td>{{ fmtTime .Time }}</td>
    <td class="sev-{{ .Severity }}">{{ .Severity }}</td>
    <td>fleet:{{ .Rule }}</td>
    <td>{{ .Summary }}</td>
    <td><a href="/events/{{ .ID }}">details</a></td>
  </tr>
  {{ end }}
</table>
{{ end }}
{{ template "foot" . }}{{ end }}

{{ define "iocs" }}{{ template "head" . }}
<h1>indicators of compromise</h1>
<p class="note">De-duplicated indicators distilled from every event: source IPs,
TLS/SSH fingerprints, ASNs, DNS names, CVE ids, captured-payload SHA-256s,
harvested C2 URLs, credentials, MACs. First sightings of the high-value types are
also logged as <code>ioc:&lt;type&gt;</code> events (stored + forwarded). JSON at
<a href="/api/iocs">/api/iocs</a>.</p>
<form method="get" action="/iocs">
  type: <input type="text" name="type" value="{{ .TypeFilter }}" placeholder="sha256" size="10">
  contains: <input type="text" name="q" placeholder="value substring" size="16">
  since: <input type="text" name="since" value="{{ .SinceStr }}" placeholder="168h" size="6">
  <button type="submit">filter</button>
  <a href="/iocs">reset</a>
</form>
{{ if not .IOCs }}
<p class="note">No indicators in the window yet.</p>
{{ else }}
<h2>by type</h2>
<p class="note">Each bar filters to that indicator type.</p>
{{ template "bars" .Counts }}
<h2>indicators ({{ .Total }})</h2>
<table>
  <tr><th>type</th><th>value</th><th>count</th><th>sev</th><th>first seen</th><th>last seen</th><th>last rule</th><th></th></tr>
  {{ range .IOCs }}
  <tr>
    <td><a href="/iocs?type={{ .Type }}">{{ .Type }}</a></td>
    <td class="mono">{{ .Value }}</td>
    <td>{{ .Count }}</td>
    <td class="sev-{{ .Severity }}">{{ .Severity }}</td>
    <td>{{ fmtTime .FirstSeen }}</td>
    <td>{{ fmtTime .LastSeen }}</td>
    <td>{{ .LastRule }}</td>
    <td><a href="{{ .Link }}">events</a></td>
  </tr>
  {{ end }}
</table>
{{ end }}
{{ template "foot" . }}{{ end }}

{{ define "tunnels" }}{{ template "head" . }}
<h1>tunnels &amp; covert transport — last 24 hours</h1>
<p class="note">Detections of tunnelling / covert channels the sensor observes. <strong>These are detections, not established tunnels</strong> — the honeypot terminates connections, it doesn't carry SSH/SOCKS/k8s/service-mesh pivots. See <a href="/docs">docs</a> and <code>list-unavailable-capabilities</code> for what is and isn't captured.</p>
<h2>by type</h2>
{{ if .Types }}{{ template "bars" .Types }}{{ else }}<p class="note">no tunnel / covert-transport detections in the window</p>{{ end }}
{{ if .Sources }}<h2>by source</h2>
<table><tr><th>source</th><th>detections</th><th>kinds</th></tr>
{{ range .Sources }}<tr><td><a href="/profiles/{{ .IP }}">{{ .IP }}</a></td><td>{{ .Count }}</td><td>{{ range .Kinds }}<span class="tag warn">{{ . }}</span> {{ end }}</td></tr>{{ end }}
</table>{{ end }}
<h2>recent</h2>
{{ if .Recent }}<table><tr><th>time</th><th>source</th><th>kind</th><th>detail</th></tr>
{{ range .Recent }}<tr><td style="white-space:nowrap">{{ fmtTime .Time }}</td><td><a href="/profiles/{{ .Source }}">{{ .Source }}</a></td><td><span class="tag warn">{{ .Kind }}</span></td><td>{{ .Detail }}</td></tr>{{ end }}
</table>{{ else }}<p class="note">none</p>{{ end }}
{{ template "foot" . }}{{ end }}

{{ define "search" }}{{ template "head" . }}
<h1>advanced search</h1>
<form method="get" action="/search">
  <table class="chart">
  <tr><td>source IP</td><td><input type="text" name="source" value="{{ .Q.SourceIP }}" size="18"></td>
      <td>rule</td><td><input type="text" name="rule" value="{{ .Q.RuleID }}" size="20"></td></tr>
  <tr><td>severity ≥</td><td><input type="text" name="severity" value="{{ .Q.Severity }}" placeholder="low|medium|high|critical" size="12"></td>
      <td>handler</td><td><input type="text" name="handler" value="{{ .Q.Handler }}" size="14"></td></tr>
  <tr><td>dest port</td><td><input type="text" name="port" value="{{ .Q.Port }}" size="8"></td>
      <td>since</td><td><input type="text" name="since" value="{{ .Q.Since }}" placeholder="24h" size="8"></td></tr>
  <tr><td>ATT&amp;CK tactic</td><td><input type="text" name="tactic" value="{{ .Q.Tactic }}" placeholder="credential-access" size="18"></td>
      <td>country</td><td><input type="text" name="country" value="{{ .Q.Country }}" size="6"></td></tr>
  <tr><td>tool</td><td><input type="text" name="tool" value="{{ .Q.Tool }}" placeholder="nmap / sqlmap / …" size="16"></td>
      <td>full-text</td><td><input type="text" name="q" value="{{ .Q.Text }}" placeholder="rule / banner / captured meta" size="28"></td></tr>
  <tr><td colspan="2"><label><input type="checkbox" name="has_payload" value="1" {{ if .Q.HasPayload }}checked{{ end }}> has payload</label>
      <label><input type="checkbox" name="has_session" value="1" {{ if .Q.HasSession }}checked{{ end }}> has session</label></td>
      <td colspan="2"><button type="submit">search</button> <a href="/search">reset</a></td></tr>
  </table>
</form>
<p class="note">Structured columns use the SQL store; tactic / country / tool / payload / session are behavioral post-filters over the captured meta. {{ if .Searched }}<strong>{{ .Matched }}</strong> match(es){{ if .Capped }} (capped){{ end }}.{{ end }}</p>
{{ if .Searched }}{{ if .Results }}<table>
<tr><th>time</th><th>severity</th><th>source</th><th>rule</th><th>handler</th><th></th></tr>
{{ range .Results }}<tr>
  <td style="white-space:nowrap">{{ fmtTime .Time }}</td>
  <td class="sev-{{ .Severity.String }}">{{ .Severity.String }}</td>
  <td><a href="/profiles/{{ .Source.IP }}">{{ .Source.IP }}</a></td>
  <td>{{ .RuleID }}</td>
  <td>{{ .Handler }}{{ if .Dest.Port }}:{{ .Dest.Port }}{{ end }}</td>
  <td><a href="/events/{{ .ID }}">details</a></td>
</tr>{{ end }}
</table>{{ else }}<p class="note">no matches</p>{{ end }}{{ end }}
{{ template "foot" . }}{{ end }}

{{ define "health" }}{{ template "head" . }}
<h1>sensor health</h1>
{{ if not .Available }}<p class="note">live metrics provider not wired (run via <code>tarpit-honeypot run</code>); showing Go runtime only.</p>{{ end }}

<h2>process</h2>
<table>
{{ if .Version }}<tr><th>build</th><td>{{ .Version }}{{ if .Commit }} ({{ .Commit }}){{ end }}</td></tr>{{ end }}
<tr><th>uptime</th><td>{{ if .Uptime }}{{ .Uptime }}{{ else }}n/a{{ end }}</td></tr>
<tr><th>runtime</th><td>{{ .GoVersion }} · GOMAXPROCS {{ .GOMAXPROCS }} · {{ .NumCPU }} CPU(s)</td></tr>
<tr><th>goroutines</th><td>{{ .Goroutines }}</td></tr>
<tr><th>memory</th><td>{{ printf "%.1f" .MemAllocMB }} MiB in use · {{ printf "%.1f" .MemSysMB }} MiB from OS · {{ printf "%.0f" .HeapObjects }} heap objects</td></tr>
<tr><th>garbage collector</th><td>{{ .NumGC }} cycles · {{ printf "%.1f" .GCPauseMs }} ms total pause · next at {{ printf "%.1f" .NextGCMB }} MiB</td></tr>
<tr><th class="{{ if gt .Panics 0 }}sev-high{{ end }}">recovered panics</th><td>{{ .Panics }}{{ if .PanicByName }} ({{ range .PanicByName }}{{ .Label }}={{ .Value }} {{ end }}){{ end }}</td></tr>
</table>

<h2>storage</h2>
<table>
<tr><th>event DB</th><td>{{ .DBSize }}</td></tr>
{{ if .DiskKnown }}<tr><th class="{{ if gt .DiskPct 90 }}sev-high{{ end }}">data_dir disk</th><td>{{ .DiskPct }}% used</td></tr>{{ else }}<tr><th>data_dir disk</th><td>n/a (no statfs on this platform)</td></tr>{{ end }}
<tr><th>events / 24h</th><td>{{ .Events24h }}{{ if .ByProto }} ({{ range .ByProto }}{{ .Label }}={{ .Value }} {{ end }}){{ end }}</td></tr>
</table>

<h2>L2 capture (sniffer)</h2>
{{ if .SnifferActive }}<div class="counters">{{ range .Frames }}<span class="counter"><b>{{ .Value }}</b><span>{{ .Label }}</span></span>{{ end }}</div>
<p class="note">Frames seen on the AF_PACKET capture sockets since start.</p>
{{ else }}<p class="note">sniffer not running (disabled, no CAP_NET_RAW, or non-Linux) — no L2 frame counters.</p>{{ end }}

<h2>event delivery (sinks)</h2>
{{ if .Sinks }}<table><tr><th>channel</th><th>dropped</th><th>failed</th><th>retried</th></tr>
{{ range .Sinks }}<tr><td>{{ .Channel }}</td><td class="{{ if gt .Dropped 0 }}sev-high{{ end }}">{{ .Dropped }}</td><td class="{{ if gt .Failed 0 }}sev-high{{ end }}">{{ .Failed }}</td><td>{{ .Retried }}</td></tr>{{ end }}
</table>
{{ if or (gt .DropTotal 0) (gt .FailTotal 0) }}<p class="note">⚠ {{ .DropTotal }} dropped + {{ .FailTotal }} failed event(s) — a sink is backlogged or down; events were lost.</p>{{ else }}<p class="note">no dropped or failed events — delivery healthy.</p>{{ end }}
{{ else }}<p class="note">no sink stats available</p>{{ end }}

{{ if .Available }}<h2>honeynet</h2>
<p>{{ .HoneyNets }} network(s) · {{ .HoneyHosts }} virtual host(s)</p>{{ end }}
{{ if .Charts }}<h2>charts</h2>
<div class="charts-grid">{{ range .Charts }}{{ template "chartfig" . }}{{ end }}</div>{{ end }}
<p class="note">Prometheus-format metrics at <a href="/metrics">/metrics</a>. Full analytics at <a href="/charts">charts</a>.</p>
{{ template "foot" . }}{{ end }}

{{ define "events" }}{{ template "head" . }}
<h1>events</h1>
<form method="get" action="/events">
  source: <input type="text" name="source" value="{{ .Filter.SourceIP }}" size="15">
  rule: <input type="text" name="rule" value="{{ .Filter.RuleID }}" size="20">
  severity: <input type="text" name="severity" value="{{ .SeverityStr }}" placeholder="low" size="8">
  since: <input type="text" name="since" value="{{ .SinceStr }}" placeholder="24h" size="6">
  limit: <input type="number" name="limit" value="{{ .Filter.Limit }}" min="1" max="1000" size="5">
  <br>search: <input type="text" name="q" value="{{ .QStr }}" placeholder="full-text: rule / banner / captured meta" size="40">
  <button type="submit">filter</button>
  <a href="/events">reset</a>
</form>
<p class="note">Click a column header to sort; click again to reverse.</p>
<p class="note">Download recorded artifacts for this filter (ZIP):
  <a href="/download?source={{ .Filter.SourceIP }}&amp;rule={{ .Filter.RuleID }}&amp;since={{ .SinceStr }}&amp;what=all">pcaps + sessions</a> ·
  <a href="/download?source={{ .Filter.SourceIP }}&amp;rule={{ .Filter.RuleID }}&amp;since={{ .SinceStr }}&amp;what=pcap">pcaps</a> ·
  <a href="/download?source={{ .Filter.SourceIP }}&amp;rule={{ .Filter.RuleID }}&amp;since={{ .SinceStr }}&amp;what=session">sessions</a>
</p>
<table>
  <tr>
    <th><a href="{{ .Headers.time.Href }}">time (utc){{ .Headers.time.Arrow }}</a></th>
    <th data-help="Reported severity. An ⌾ override badge means a local severity_overrides rule pinned this level; the event detail shows the default and the rule."><a href="{{ .Headers.severity.Href }}">severity{{ .Headers.severity.Arrow }}</a></th>
    <th><a href="{{ .Headers.rule.Href }}">rule{{ .Headers.rule.Arrow }}</a></th>
    <th><a href="{{ .Headers.source.Href }}">source{{ .Headers.source.Arrow }}</a></th>
    <th data-help="Destination the attacker reached: IP:port, the service name, and a transport tag (tcp / udp / icmp / l2).">dest</th>
    <th><a href="{{ .Headers.handler.Href }}">handler{{ .Headers.handler.Arrow }}</a></th>
    <th></th>
  </tr>
  {{ range .Events }}
  <tr>
    <td>{{ fmtTime .Time }}</td>
    <td class="sev-{{ .Severity }}">{{ .Severity }}{{ if .SeverityOverridden }} <span class="ovr" title="local override — default severity {{ index .Meta "default_severity" }} (rule {{ index .Meta "severity_override_rule" }})">⌾ override</span>{{ end }}</td>
    <td>{{ .RuleID }}</td>
    <td>{{ .Source.IP }}{{ if .Source.Port }}:{{ .Source.Port }}{{ end }}</td>
    <td>{{ .Dest.IP }}{{ if .Dest.Port }}:{{ .Dest.Port }}{{ if svcName .Dest.Port }} <span class="svc">{{ svcName .Dest.Port }}</span>{{ end }}{{ end }}{{ if .Proto }} <span class="proto proto-{{ .Proto }}" title="transport: {{ .Proto }}">{{ .Proto }}</span>{{ end }}</td>
    <td>{{ .Handler }}</td>
    <td><a href="/events/{{ .ID }}">details</a></td>
  </tr>
  {{ end }}
</table>
{{ template "foot" . }}{{ end }}

{{ define "event" }}{{ template "head" . }}
<h1>event {{ .ID }}</h1>
<table>
  <tr><th>time</th><td>{{ fmtTime .Time }}</td></tr>
  <tr><th>sensor</th><td>{{ .Sensor }}</td></tr>
  <tr><th>rule_id</th><td>{{ .RuleID }}</td></tr>
  <tr><th>severity</th><td class="sev-{{ .Severity }}">{{ .Severity }}{{ if .SeverityOverridden }} <span class="ovr">⌾ local override</span> — default was <b>{{ index .Meta "default_severity" }}</b>, pinned by <code>severity_overrides</code> rule <code>{{ index .Meta "severity_override_rule" }}</code>{{ end }}</td></tr>
  <tr><th>source</th><td>{{ .Source.IP }}:{{ .Source.Port }}</td></tr>
  <tr><th>dest</th><td>{{ .Dest.IP }}:{{ .Dest.Port }}{{ if svcName .Dest.Port }} ({{ svcName .Dest.Port }}){{ end }}</td></tr>
  <tr><th>proto</th><td>{{ if .Proto }}<span class="proto proto-{{ .Proto }}">{{ .Proto }}</span>{{ else }}—{{ end }}</td></tr>
  <tr><th>handler</th><td>{{ .Handler }}</td></tr>
</table>

{{ if .MitreTechniques }}<h2>ATT&amp;CK / D3FEND</h2><table>
  <tr><th>techniques</th><td>{{ range .MitreTechniques }}<a class="tag" href="/attack/technique?id={{ . }}" title="{{ techDesc . }}">{{ . }}</a> {{ end }}</td></tr>
  {{ if .MitreTactics }}<tr><th>tactics</th><td>{{ range .MitreTactics }}<span class="tag">{{ . }}</span> {{ end }}</td></tr>{{ end }}
  {{ if .MitreDefenses }}<tr><th>D3FEND</th><td>{{ range .MitreDefenses }}<span class="tag">{{ . }}</span> {{ end }}</td></tr>{{ end }}
</table>{{ end }}

<h2>downloads</h2>
<ul>
  <li><a href="/pcap/{{ .ID }}">pcap</a> (per-connection capture, if recorded)</li>
  {{ if index .Meta "session_cast" }}<li><a href="/session/{{ .ID }}">session recording</a> (asciinema cast)</li>{{ end }}
  {{ if .Source.IP }}<li><a href="/download?source={{ .Source.IP }}&amp;since=720h">all pcaps + sessions from {{ .Source.IP }}</a> (ZIP, last 30d)</li>{{ end }}
</ul>

{{ if .BannerSent }}<h2>banner sent</h2><div class="kv">{{ .BannerSent }}</div>{{ end }}
{{ if .PayloadBase64 }}<h2>payload ({{ .PayloadLen }} bytes)</h2>
{{ $hex := hexdump .PayloadBase64 }}{{ if $hex }}<div class="kv">{{ $hex }}</div>{{ else }}<div class="kv">{{ .PayloadBase64 }}</div>{{ end }}
<details><summary class="note">base64</summary><div class="kv">{{ .PayloadBase64 }}</div></details>{{ end }}
{{ if .Meta }}<h2>meta</h2><table>
{{ range $k, $v := .Meta }}<tr><th>{{ $k }}</th><td>{{ $v }}</td></tr>{{ end }}
</table>{{ end }}
{{ template "foot" . }}{{ end }}

{{ define "profiles" }}{{ template "head" . }}
<h1>attacker profiles</h1>
<p class="note">One dossier per source IP, compiled from behaviour, tool / scanner
fingerprinting, credentials tried, and ATT&amp;CK technique observation — it builds up
as the source keeps interacting. Ranked by a severity-weighted threat score. JSON at
<a href="/api/profiles">/api/profiles</a>.</p>
<form method="get" action="/profiles">
  since: <input type="text" name="since" value="{{ .SinceStr }}" placeholder="720h" size="6">
  <button type="submit">filter</button>
  <a href="/profiles">reset</a>
</form>
{{ if not .Profiles }}
<p class="note">No sources observed in the window.</p>
{{ else }}
<table>
  <tr><th>source ip</th><th>threat</th><th>max severity</th><th>events</th><th>distinct rules</th><th>first seen</th><th>last seen</th></tr>
  {{ range .Profiles }}
  <tr>
    <td><a href="/profiles/{{ .IP }}">{{ .IP }}</a></td>
    <td>{{ .Weight }}</td>
    <td class="sev-{{ .MaxSeverity }}">{{ .MaxSeverity }}</td>
    <td>{{ .Count }}</td>
    <td>{{ .DistinctRules }}</td>
    <td>{{ fmtTime .FirstSeen }}</td>
    <td>{{ fmtTime .LastSeen }}</td>
  </tr>
  {{ end }}
</table>
{{ end }}
{{ template "foot" . }}{{ end }}

{{ define "profile" }}{{ template "head" . }}
<h1>attacker profile — {{ .IP }}</h1>
{{ if .Classification }}<div class="depl"><b>assessment:</b> <span class="threat-{{ .ThreatLevel }}">{{ .Classification }}</span></div>
<p class="note">{{ .Summary }}</p>{{ end }}
<div class="depl">
  threat: <span class="threat-{{ .ThreatLevel }}">{{ .ThreatLevel }} ({{ .ThreatScore }})</span> ·
  max severity: <span class="sev-{{ .MaxSeverity }}">{{ .MaxSeverity }}</span> ·
  {{ .Count }} event(s){{ if .Partial }}+{{ end }} ·
  {{ if .Automation }}automation{{ else }}unflagged{{ end }}
  {{ if .Confidence }} · id confidence: <span class="tag">{{ confLabel .Confidence }} ({{ .Confidence }})</span>{{ end }}
  {{ if .Sensors }} · sensors: {{ range .Sensors }}<span class="tag">{{ . }}</span>{{ end }}{{ end }}
</div>
<p class="note">first seen {{ fmtTime .FirstSeen }} · last seen {{ fmtTime .LastSeen }} ·
  <a href="/events?source={{ .IP }}&amp;since=2160h">all events</a> ·
  <a href="/download?source={{ .IP }}&amp;since=2160h&amp;what=all">artifacts (ZIP)</a> ·
  <a href="/api/profiles/{{ .IP }}">JSON</a></p>

<h2>events by severity</h2>
<table><tr><th>severity</th><th>count</th></tr>
{{ range $k, $v := .BySeverity }}<tr><td class="sev-{{ $k }}">{{ $k }}</td><td>{{ $v }}</td></tr>{{ end }}
</table>

{{ if .Tools }}<h2>tools / scanners</h2><div>{{ range .Tools }}<span class="tag bad">{{ . }}</span>{{ end }}</div>{{ end }}

{{ if .Fingerprints }}<h2>fingerprints</h2><table>
{{ range $k, $v := .Fingerprints }}<tr><th>{{ $k }}</th><td><a href="/fingerprints/{{ $k }}/{{ $v }}">{{ $v }}</a></td></tr>{{ end }}
</table>
<p class="note">Fingerprint links open a cross-sensor reputation report (where else this client stack has been seen).</p>{{ end }}

{{ if .Handlers }}<h2>services targeted</h2><div>{{ range .Handlers }}<span class="tag">{{ . }}</span>{{ end }}</div>
{{ if .Ports }}<p class="note">ports: {{ join .Ports }}</p>{{ end }}{{ end }}

{{ if .Mitre }}<h2>ATT&amp;CK techniques</h2><div>{{ range .Mitre }}<a href="/attack/technique?id={{ . }}" class="tag warn">{{ . }}</a> {{ end }}</div>{{ end }}
{{ if .Tactics }}<h2>ATT&amp;CK tactics</h2><div>{{ range .Tactics }}<span class="tag warn">{{ . }}</span>{{ end }}</div>{{ end }}

{{ if .CVEs }}<h2>CVE exploit attempts</h2><div>{{ range .CVEs }}<span class="tag bad">{{ . }}</span>{{ end }}</div>{{ end }}

{{ if .Anomalies }}<h2>anomalies</h2><div>{{ range .Anomalies }}<span class="tag warn">{{ . }}</span>{{ end }}</div>{{ end }}

{{ if .Credentials }}<h2>credentials tried</h2><table><tr><th>username</th><th>password</th><th>service</th></tr>
{{ range .Credentials }}<tr><td>{{ .User }}</td><td>{{ .Pass }}</td><td>{{ if .Service }}<span class="tag">{{ .Service }}</span>{{ else }}—{{ end }}</td></tr>{{ end }}
</table>{{ end }}

{{ if .Rules }}<h2>triggered rules</h2><table><tr><th><a href="{{ .RuleHeaders.Rule.Href }}">rule{{ .RuleHeaders.Rule.Arrow }}</a></th><th><a href="{{ .RuleHeaders.Count.Href }}">count{{ .RuleHeaders.Count.Arrow }}</a></th></tr>
{{ range .Rules }}<tr><td><a href="/events?source={{ $.IP }}&amp;rule={{ .Name }}">{{ .Name }}</a></td><td>{{ .Count }}</td></tr>{{ end }}
</table>{{ end }}

{{ if .Sensors }}<p class="note">seen by sensor(s): {{ range .Sensors }}{{ . }} {{ end }}</p>{{ end }}

<h2>recent events</h2>
<table><tr><th>time (utc)</th><th>severity</th><th>rule</th><th>handler</th><th></th></tr>
{{ range .Recent }}<tr>
  <td>{{ fmtTime .Time }}</td>
  <td class="sev-{{ .Severity }}">{{ .Severity }}</td>
  <td>{{ .RuleID }}</td>
  <td>{{ .Handler }}</td>
  <td><a href="/events/{{ .ID }}">details</a></td>
</tr>{{ end }}
</table>
{{ template "foot" . }}{{ end }}

{{ define "fingerprints" }}{{ template "head" . }}
<h1>fingerprint reputation</h1>
<p class="note">Network fingerprints (JA3 / JA4 / JA4H / JA3S / HASSH) seen in the
last {{ .Window }}, ranked by event volume. A fingerprint identifies the
client TLS/SSH stack, so the same value recurring across many source IPs,
ASNs, or sensors is a strong tool / campaign signal. JSON at
<a href="/api/fingerprints">/api/fingerprints</a>.</p>
{{ if not .Rows }}<p class="note">No fingerprints recorded yet. They appear once a
client completes a TLS ClientHello or sends an SSH banner to a listener.</p>
{{ else }}
<table>
<tr><th>kind</th><th>fingerprint</th><th>events</th><th>distinct IPs</th><th>sensors</th><th>first seen</th><th>last seen</th></tr>
{{ range .Rows }}<tr>
  <td>{{ .Kind }}</td>
  <td><a href="/fingerprints/{{ .Kind }}/{{ .Value }}">{{ .Value }}</a></td>
  <td>{{ .Count }}</td>
  <td>{{ .IPs }}</td>
  <td>{{ .Sensors }}</td>
  <td>{{ fmtTime .FirstSeen }}</td>
  <td>{{ fmtTime .LastSeen }}</td>
</tr>{{ end }}
</table>
{{ end }}
{{ template "foot" . }}{{ end }}

{{ define "fingerprint" }}{{ template "head" . }}
<h1>fingerprint — {{ .Kind }}</h1>
<div class="kv">{{ .Value }}</div>
<div class="depl">
  {{ .Count }} event(s){{ if .Partial }}+{{ end }} ·
  {{ .IPs }} distinct source IP(s) ·
  {{ len .Sensors }} sensor(s)
</div>
<p class="note">first seen {{ fmtTime .FirstSeen }} · last seen {{ fmtTime .LastSeen }} ·
  <a href="/api/fingerprints/{{ .Kind }}/{{ .Value }}">JSON</a></p>

{{ if .Sensors }}<h2>sensors (fleet correlation)</h2>{{ template "bars" .Sensors }}{{ end }}
{{ if .TopIPs }}<h2>top source IPs</h2>{{ template "bars" .TopIPs }}{{ end }}
{{ if .Countries }}<h2>countries</h2>{{ template "bars" .Countries }}{{ end }}
{{ if .ASNs }}<h2>ASNs</h2>{{ template "bars" .ASNs }}{{ end }}
{{ if .Protocols }}<h2>protocols</h2>{{ template "bars" .Protocols }}{{ end }}
{{ if .Ports }}<h2>destination ports</h2>{{ template "bars" .Ports }}{{ end }}
{{ if .Rules }}<h2>attack types (rules)</h2>{{ template "bars" .Rules }}{{ end }}
{{ if .Tools }}<h2>tools / scanners</h2>{{ template "bars" .Tools }}{{ end }}
{{ if .Malware }}<h2>captured malware artifacts</h2>{{ template "bars" .Malware }}{{ end }}
{{ template "foot" . }}{{ end }}

{{ define "config" }}{{ template "head" . }}
<h1>effective configuration</h1>
{{ if .Themes }}
<h2>UI theme</h2>
<p class="note">Pick a theme — applied via a per-browser cookie, persists across reloads. <code>default</code> clears the cookie.</p>
<div class="theme-picker">
{{ range .Themes }}<a class="themelink{{ if .Active }} active{{ end }}" href="{{ .Href }}" title="{{ .Desc }}"><span class="swatch" style="background:{{ .Swatch }}"></span>{{ .Label }}</a>{{ end }}
</div>
{{ end }}
{{ if .Sizes }}
<h2>text size</h2>
<p class="note">Scale the whole UI's typography. Persists per browser; <code>normal</code> clears the cookie.</p>
<div class="theme-picker">
{{ range .Sizes }}<a class="themelink{{ if .Active }} active{{ end }}" href="{{ .Href }}" title="{{ .Sample }}">{{ .Label }}</a>{{ end }}
</div>
{{ end }}
{{ with .Canvas }}
<h2>infrastructure canvas</h2>
<p class="note">What this sensor is actually running: {{ .ListenerCount }} listener(s)
({{ .TCPCount }} tcp / {{ .UDPCount }} udp) · {{ .ActiveCollector }} active collector(s).
JSON at <a href="/api/config/canvas">/api/config/canvas</a>.</p>
{{ if .Listeners }}
<div class="canvas-grid">
  {{ range .Listeners }}
  <div class="pcard mode-{{ .Mode }}">
    <div class="pcard-top"><span class="proto proto-{{ .Proto }}">{{ .Proto }}</span><span class="pcard-port">{{ .PortLabel }}</span></div>
    <div class="pcard-svc">{{ if .Service }}{{ .Service }}{{ else }}{{ .Handler }}{{ end }}</div>
    <div class="pcard-meta">{{ .Handler }} · {{ .Mode }}</div>
    <div>{{ if .TLS }}<span class="ctag tls">tls</span>{{ end }}{{ if .Capture }}<span class="ctag cap">pcap</span>{{ end }}{{ if .Archetype }}<span class="ctag">{{ .Archetype }}</span>{{ end }}</div>
  </div>
  {{ end }}
</div>
{{ else }}<p class="note">No listeners configured.</p>{{ end }}

<h2>collectors</h2>
<p class="note">Background subsystems — <span class="coll on">green</span> = active, <span class="coll off">grey</span> = available but off.</p>
{{ range .Groups }}
<div class="coll-group"><span class="coll-cat">{{ .Title }}</span>
  {{ range .Items }}<span class="coll {{ if .Active }}on{{ else }}off{{ end }}" title="{{ .Detail }}">{{ .Name }}{{ if and .Active .Detail }} <span class="coll-detail">{{ .Detail }}</span>{{ end }}</span>{{ end }}
</div>
{{ end }}
{{ end }}

{{ if .Files }}
<h2>files in use</h2>
<p class="note">Config files, enrichment inputs, and databases this sensor reads, plus
the data-dir state it writes. <b class="sev-high">MISSING</b> = a configured input
not present on disk. Same data via <code>tarpit-honeypot list-paths</code>.</p>
<table>
  <tr><th>category</th><th>key</th><th>access</th><th>path</th><th>status</th></tr>
  {{ range .Files }}<tr>
    <td><span class="tag">{{ .Category }}</span></td>
    <td>{{ .Key }}</td>
    <td>{{ .Access }}</td>
    <td><code>{{ .Path }}</code></td>
    <td>{{ if .Exists }}present{{ else if eq .Access "write" }}pending{{ else }}<b class="sev-high">MISSING</b>{{ end }}</td>
  </tr>{{ end }}
</table>
{{ end }}

<h2>full configuration (YAML)</h2>
<p class="note">Post-defaults config the sensor is running with. Secrets are shown
as their environment-variable names (<code>*_env</code>), never expanded values,
so this is safe to copy into a ticket. Raw YAML also at <a href="/api/config">/api/config</a>.</p>
<div class="kv">{{ .YAML }}</div>
{{ template "foot" . }}{{ end }}

{{ define "topology" }}{{ template "head" . }}
<h1>honeynet topology</h1>
{{ if not .Networks }}
<p class="note">No honeynet configured. Add a <code>honeynets:</code> block (virtual
networks of hosts + services the sensor answers for) to populate this view.
JSON at <a href="/api/topology">/api/topology</a>.</p>
{{ else }}
<p class="note">Infrastructure map: virtual networks the sensor presents, with live
attack activity (last 24h) overlaid per host. JSON at <a href="/api/topology">/api/topology</a>.
{{ if not .Active }}<br>No attack activity recorded against these hosts yet.{{ end }}</p>
{{ if .Graph.B64 }}{{ template "chartfig" .Graph }}{{ end }}
{{ range .Networks }}
<div class="net">
  <h3>{{ .ID }}{{ if .CIDR }} — {{ .CIDR }}{{ end }}{{ if .Events }} <span class="sev-high">⚠ {{ .Events }} events / {{ .Attackers }} attacker(s)</span>{{ end }}</h3>
  <div class="meta">
    {{ if .Domain }}domain {{ .Domain }} · {{ end }}
    {{ if .Gateway }}gw {{ .Gateway }} · {{ end }}
    {{ if .DNS }}dns {{ .DNS }} · {{ end }}
    {{ len .Hosts }} host(s)
  </div>
  {{ range .Hosts }}
  <div class="host">
    <div class="hostline">{{ .IP }}{{ if .Hostname }} · {{ .Hostname }}{{ end }}
      {{ if .OS }}<span class="os">({{ .OS }})</span>{{ end }}
      {{ if .MAC }}<span class="os">{{ .MAC }}</span>{{ end }}
      {{ if .Events }}<span class="tag bad sev-{{ .MaxSev }}">{{ .Events }} events · {{ .Attackers }} attacker(s) · {{ .MaxSev }}</span>{{ else }}<span class="tag">quiet</span>{{ end }}
    </div>
    {{ range .Services }}<span class="svc">{{ .Port }}/{{ .Handler }}</span>{{ end }}
    {{ if .Events }}<span class="note">last hit {{ fmtTime .LastSeen }} · <a href="/events?source=&amp;rule=">events</a></span>{{ end }}
  </div>
  {{ end }}
</div>
{{ end }}
{{ end }}
{{ template "foot" . }}{{ end }}

{{ define "devices" }}{{ template "head" . }}
<h1>known / seen devices</h1>
{{ if not .Enabled }}<p class="note">Device tracking is disabled. Set
<code>devices.enabled: true</code> to learn devices from DHCP, the ARP sniffer,
broadcast/multicast discovery, and connection source IPs.</p>{{ end }}
{{ if .Notice }}<p class="depl">{{ .Notice }}</p>{{ end }}
{{ with .Summary }}
<div class="depl">
  inventory: <b>{{ .Total }}</b> total · <b>{{ .Allowed }}</b> allow-listed · <b>{{ .Rogue }}</b> rogue
  {{ if .BySource }}<br>by source: {{ range .BySource }}<span class="tag">{{ .Label }}={{ .Count }}</span>{{ end }}{{ end }}
  {{ if .ByClass }}<br>by class: {{ range .ByClass }}<span class="tag">{{ .Label }}={{ .Count }}</span>{{ end }}{{ end }}
</div>
{{ if .Conflicts }}
<div class="depl"><b>&#9888; IP/MAC conflicts</b> — one address claimed by multiple MACs (possible ARP spoof / impersonation):
<table>
  <tr><th>ip</th><th>macs</th></tr>
  {{ range .Conflicts }}<tr><td><a href="/profiles/{{ .IP }}">{{ .IP }}</a></td><td>{{ range .MACs }}<span class="tag">{{ . }}</span>{{ end }}</td></tr>{{ end }}
</table>
</div>
{{ end }}
{{ end }}
<form method="get" action="/devices">
  filter: <input type="text" name="q" value="{{ .Query }}" placeholder="ip / mac / hostname / vendor / service" size="28">
  status: <select name="status">
    <option value=""{{ if eq .Status "" }} selected{{ end }}>all</option>
    <option value="seen"{{ if eq .Status "seen" }} selected{{ end }}>seen</option>
    <option value="allow"{{ if eq .Status "allow" }} selected{{ end }}>allow-listed</option>
  </select>
  <button type="submit">filter</button>
  <a href="/devices">reset</a>
</form>
{{ if not .Hosts }}
<p class="note">No devices learned yet. JSON at <a href="/api/devices">/api/devices</a>.</p>
{{ else }}
<p class="note">Devices the sensor has observed (IPv4 / IPv6 / MAC), with the
services/ports they touched and learned attributes — knowledge accrues over
time. "allow" = whitelisted (won't raise <code>device:new</code>).
{{ if .ActionsEnabled }} Write actions are <b>enabled</b>.{{ else }} Actions are read-only ( set <code>ui.allow_device_actions: true</code> + an auth token to manage devices here).{{ end }}
JSON at <a href="/api/devices">/api/devices</a>.</p>
<table>
  <tr><th>ip</th><th>mac</th><th>hostname</th><th>vendor</th><th>source</th><th>status</th><th>services</th><th>ports</th><th>attrs</th><th>last seen</th><th>count</th>{{ if .ActionsEnabled }}<th>actions</th>{{ end }}</tr>
  {{ range .Hosts }}
  <tr>
    <td>{{ if .IP }}<a href="/profiles/{{ .IP }}">{{ .IP }}</a>{{ end }}</td>
    <td>{{ .MAC }}</td>
    <td>{{ .Hostname }}</td>
    <td>{{ .Vendor }}</td>
    <td>{{ .Source }}</td>
    <td>{{ if .Allowed }}allow{{ else }}seen{{ end }}</td>
    <td>{{ range .Services }}<span class="tag">{{ . }}</span>{{ end }}</td>
    <td>{{ join .Ports }}</td>
    <td>{{ range $k, $v := .Attrs }}<span class="tag">{{ $k }}={{ $v }}</span>{{ end }}</td>
    <td>{{ fmtTime .LastSeen }}</td>
    <td>{{ .Count }}</td>
    {{ if $.ActionsEnabled }}<td>
      {{ if not .Allowed }}<form method="post" action="/devices/action"><input type="hidden" name="token" value="{{ $.Token }}"><input type="hidden" name="key" value="{{ .Key }}"><input type="hidden" name="action" value="allow"><button type="submit">whitelist</button></form>{{ end }}
      <form method="post" action="/devices/action"><input type="hidden" name="token" value="{{ $.Token }}"><input type="hidden" name="key" value="{{ .Key }}"><input type="hidden" name="action" value="delete"><button type="submit">delete</button></form>
    </td>{{ end }}
  </tr>
  {{ end }}
</table>
{{ end }}
{{ template "foot" . }}{{ end }}

{{ define "alerting" }}{{ template "head" . }}
<h1>alerting &amp; event forwarding</h1>
<p class="note">How this sensor forwards events. Secrets show as their
<code>*_env</code> names. JSON at <a href="/api/alerting">/api/alerting</a>.</p>
<div class="depl">
  syslog: {{ if .HasSyslog }}<b>configured</b>{{ else }}off{{ end }} ·
  email: {{ if .HasEmail }}<b>configured</b>{{ else }}off{{ end }} ·
  webhook: {{ if .HasWebhook }}<b>configured</b>{{ else }}off{{ end }} ·
  sms: {{ if .HasSMS }}<b>configured</b>{{ else }}off{{ end }} ·
  snmp-trap: {{ if .HasSNMP }}<b>configured</b>{{ else }}off{{ end }}
</div>

<h2>channels</h2>
<table>
  <tr><th>id</th><th>type</th><th>destination</th><th>format</th><th>min severity</th><th>rate/min</th><th>scope</th></tr>
  {{ range .Channels }}
  <tr>
    <td>{{ .ID }}</td>
    <td>{{ .Type }}</td>
    <td>{{ .Destination }}</td>
    <td>{{ .Format }}</td>
    <td>{{ .MinSeverity }}</td>
    <td>{{ if .RateLimit }}{{ .RateLimit }}{{ end }}</td>
    <td>{{ if .Local }}local (always){{ else }}outbound{{ end }}</td>
  </tr>
  {{ end }}
</table>

<h2>routes</h2>
{{ if not .Routes }}<p class="note">No routes configured — outbound channels receive per their own gates.</p>{{ else }}
<table>
  <tr><th>match</th><th>channels</th></tr>
  {{ range .Routes }}<tr><td>{{ .Match }}</td><td>{{ range .Channels }}{{ . }} {{ end }}</td></tr>{{ end }}
</table>
{{ end }}

{{ if .Allowlist }}<h2>allowlist (outbound-suppressed sources)</h2>
<div class="kv">{{ range .Allowlist }}{{ . }}
{{ end }}</div>{{ end }}
{{ template "foot" . }}{{ end }}

{{ define "errors" }}{{ template "head" . }}
<h1>operational errors &amp; health</h1>
<p class="note">Sensor-side problems (listener stopped, listener start error,
canary watcher stopped, accept-cap overflow, recovered panics) — separated
from attacker-interaction events. JSON for all events at <a href="/api/events">/api/events</a>.</p>
<form method="get" action="/errors">
  since: <input type="text" name="since" value="{{ .SinceStr }}" placeholder="168h" size="6">
  <button type="submit">filter</button>
  <a href="/errors">reset</a>
</form>
{{ if not .Events }}
<p class="note">No operational errors in the window. The sensor is healthy.</p>
{{ else }}
<table>
  <tr><th>time (utc)</th><th>severity</th><th>rule</th><th>detail</th></tr>
  {{ range .Events }}
  <tr>
    <td>{{ fmtTime .Time }}</td>
    <td class="sev-{{ .Severity }}">{{ .Severity }}</td>
    <td>{{ .RuleID }}</td>
    <td><a href="/events/{{ .ID }}">details</a></td>
  </tr>
  {{ end }}
</table>
{{ end }}
{{ template "foot" . }}{{ end }}

{{ define "docs" }}{{ template "head" . }}
<div class="docs">
<h1>tarpit-honeypot — documentation</h1>
<p>A deception + detection sensor: it presents believable services (banners,
protocol emulators, virtual hosts), wastes attacker time (tarpits), and turns
every interaction into a structured, ATT&amp;CK-tagged event for your SIEM. It is
built to be a <em>target</em> — the UI is read-only, binds loopback by default,
and the sensor never becomes a reflection/amplification primitive.</p>

<h2>this deployment</h2>
<p class="depl">
{{ .Listeners }} listener(s) · {{ .Networks }} honeynet network(s) · {{ .Hosts }} virtual host(s)<br>
device tracking: {{ if .DevicesOn }}on{{ else }}off{{ end }} · ui bind: <code>{{ .UIBind }}</code>
</p>

<h2>full documentation</h2>
<p>The complete guides, rendered in-product (the same Markdown shipped under
<code>docs/</code>). Start with the <a href="/docs/webui">web UI walkthrough</a>.</p>
<div class="doclib">
{{ range .Docs }}<a class="doccard" href="/docs/{{ .Name }}"><b>{{ .Title }}</b>{{ if .Desc }}<span>{{ .Desc }}</span>{{ end }}</a>{{ end }}
</div>

<h2>tabs</h2>
<ul>
<li><a href="/">summary</a> — 24h rollup by severity, rule, and source.</li>
<li><a href="/events">events</a> — filterable event log (source, rule, severity, time).</li>
<li><a href="/profiles">profiles</a> — per-source-IP attacker dossiers (synthesized assessment + threat score, tools/scanners with identification confidence, fingerprints, credentials tried, ATT&amp;CK, targeted services), compiled over time.</li>
<li><a href="/fingerprints">fingerprints</a> — JA3 / JA4 / JA4H / JA3S / HASSH reputation: pivot from a client TLS/SSH stack to every source IP, ASN, country, protocol, port, attack type, captured malware, and <em>which sensors in the fleet</em> observed it (cross-sensor correlation).</li>
<li><a href="/devices">devices</a> — learned / seen / whitelisted devices (IPv4 / IPv6 / MAC) with the services/ports they touched + learned attributes; optional delete/whitelist actions (<code>ui.allow_device_actions</code> + auth token).</li>
<li><a href="/topology">topology</a> — the virtual networks / hosts / services the sensor presents.</li>
<li><a href="/fleet">fleet</a> — cross-sensor (fleet:*) findings: one source / ASN / fingerprint / payload / credential / CVE / tool / port / technique across many sensors, shared C2, novel infra, persistent networks. Aggregator-only (needs <code>ingest:</code>).</li>
<li><a href="/iocs">iocs</a> — de-duplicated indicators of compromise (IPs, fingerprints, ASNs, domains, CVEs, payload hashes, C2 URLs, credentials, MACs) with first/last-seen + counts; first sightings of high-value types are logged as <code>ioc:*</code> events.</li>
<li><a href="/alerting">alerting</a> — how events are forwarded (syslog / email / webhook / SMS / SNMP).</li>
<li><a href="/errors">errors</a> — operational / health events (listener or canary-watcher stopped, accept-cap overflow).</li>
<li><a href="/config">config</a> — the effective running config (secrets shown as env-var names).</li>
</ul>

<h2>detection</h2>
<ul>
<li><b>Scan analysis</b> (<code>scananalysis:profile</code>) — per-source nmap fingerprinting:
timing template (<code>-T0</code>..<code>-T5</code>) from inter-connection cadence, aggressive
(<code>-A</code>) and OS-probe (<code>-O</code>) detection, service/version-probe matching
(<code>-sV</code>), NSE-script signatures, connect-scan detection, and scan-sequencing
heuristics. SYN/FIN/NULL/Xmas/ACK scans, raw fragmentation, and decoy floods
(<code>-D</code>) require the AF_PACKET sniffer and are flagged as needing packet capture.</li>
<li><b>Protocol anomalies</b> — per-handler markers (non-printable banners, smuggled
bytes, DNS tunneling/exfil shapes, abnormal ICMP payloads, UDP amplifier probes).</li>
<li><b>Device learning</b> — learns a baseline and raises <code>device:new</code> for
never-before-seen, non-allow-listed hosts (DHCP, ARP sniffer, broadcast/multicast).</li>
<li><b>Correlation / storyline</b> — port-scan, slow-scan, brute-force, and ICMP-sweep
correlation; events carry MITRE ATT&amp;CK techniques + tactics for kill-chain pivoting.</li>
</ul>

<h2>protocol handlers</h2>
<ul>
<li><b>Auth surface</b>: ssh, ssh_interactive, telnet, ftp, ftp_files, rdp, vnc, winrm,
smb, postgres, mysql, redis, ldap, kerberos, amqp, mqtt.</li>
<li><b>Web / apps</b>: http, https (per-service certs), rtsp, ipp, dockerapi, plus vendor
gateway emulators (fortinet, pulse, citrix, esxi, idrac/ilo/amt, moxa, ...).</li>
<li><b>ICS / OT</b>: modbus, s7, iec104, opcua, ethernetip, bacnet, fins, melsec, knx.</li>
<li><b>Discovery / UDP</b>: snmp, ssdp, llmnr, nbns, cldap, sip, coap, ntp, tftp, ipmi,
radius, syslog, dhcp.</li>
<li><b>DNS</b>: <code>dns</code> answers A/AAAA/MX/TXT/NS/CNAME with fabricated, deterministic-
per-deployment records so a resolver-enumeration sees a live, populated server —
every query is run through tunneling/exfil detection.</li>
<li><b>Small services</b> (RFC 862-868, 1340): echo, discard, daytime, qotd, chargen, time —
TCP + UDP. chargen/echo are reflector favorites, so replies are strictly bounded
(one capped response) and never amplify.</li>
</ul>

<h2>tarpit modes</h2>
<ul>
<li><code>mode: tarpit</code> with <code>strategy: sticky | trickle | keepalive</code> holds the
connection open to waste scanner/worm time.</li>
<li><code>tarpit.emulate: true</code> runs the listener's protocol <code>handler:</code> first
(real banner + captured request) and <em>then</em> tarpits the same connection — any
emulator becomes a tarpit, and the captured banner/request lands in the
<code>tarpit_start</code> event.</li>
</ul>

<h2>cli</h2>
<ul>
<li><code>tarpit-honeypot run -config tarpit-honeypot.yaml</code> — start the sensor.</li>
<li><code>tarpit-honeypot validate -config ...</code> — check the config without binding.</li>
<li><code>tarpit-honeypot list-devices</code> / <code>list-honeynets</code> — inspect learned devices / topology.</li>
<li><code>tarpit-honeypot version</code> — build version. <code>SIGHUP</code> hot-reloads config.</li>
</ul>

<h2>security model</h2>
<ul>
<li>UI is read-only by default and binds loopback unless you set both TLS and a static
auth token. The only optional write action is device delete/whitelist, gated behind
<code>ui.allow_device_actions</code> + an auth token (off by default).</li>
<li>Secrets live only as <code>*_env</code> references — never expanded in config output or logs.</li>
<li>All attacker-supplied bytes are bounds-checked and sanitized before logs / SIEM / email.</li>
<li>The sensor refuses to be a reflection/amplification primitive (bounded small-service
replies, NTP mode-7 silent, no unbounded DNS answers).</li>
</ul>
</div>
{{ template "foot" . }}{{ end }}

{{ define "doc" }}{{ template "head" . }}
<div class="docs mddoc">
<p class="docnav"><a href="/docs">&larr; documentation index</a></p>
{{ .Body }}
</div>
{{ template "foot" . }}{{ end }}
`
