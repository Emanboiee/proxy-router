import {currentMonitor, getCurrentWindow, LogicalSize, PhysicalPosition, primaryMonitor} from '@tauri-apps/api/window';
import type {LayoutPreset} from './controller';

interface Rect {x: number; y: number; width: number; height: number}
const presets = {vertical: {width: 560, height: 820}, horizontal: {width: 1440, height: 900}};

/** Work area and frame are physical pixels; preset content sizes are logical. */
export function fitWindowLayout(layout: LayoutPreset, area: Rect, scale: number, frame: {width: number; height: number}, current: Rect): Rect {
  if (![area.x, area.y, area.width, area.height, scale, frame.width, frame.height, current.x, current.y, current.width, current.height].every(Number.isFinite)
    || scale <= 0 || area.width <= frame.width || area.height <= frame.height) throw new Error('Display work area unavailable');
  const width = Math.max(1, Math.floor(Math.min(presets[layout].width, (area.width - frame.width) / scale)));
  const height = Math.max(1, Math.floor(Math.min(presets[layout].height, (area.height - frame.height) / scale)));
  const outerWidth = Math.ceil(width * scale) + frame.width;
  const outerHeight = Math.ceil(height * scale) + frame.height;
  return {
    width, height,
    x: Math.floor(Math.max(area.x, Math.min(current.x + (current.width - outerWidth) / 2, area.x + area.width - outerWidth))),
    y: Math.floor(Math.max(area.y, Math.min(current.y + (current.height - outerHeight) / 2, area.y + area.height - outerHeight))),
  };
}

let pending: Promise<void> = Promise.resolve();
export function resizeNativeWindow(layout: LayoutPreset): Promise<void> {
  // Serialize rapid preset changes so an older resize cannot win last.
  pending = pending.catch(() => {}).then(async () => {
    const monitor = await currentMonitor() ?? await primaryMonitor();
    if (!monitor) throw new Error('Display work area unavailable');
    const window = getCurrentWindow();
    if (await window.isMaximized()) await window.unmaximize();
    const [inner, outer, position] = await Promise.all([window.innerSize(), window.outerSize(), window.outerPosition()]);
    const bounds = fitWindowLayout(layout, {...monitor.workArea.position, ...monitor.workArea.size}, monitor.scaleFactor,
      {width: Math.max(0, outer.width - inner.width), height: Math.max(0, outer.height - inner.height)}, {...position, ...outer});
    await window.setSize(new LogicalSize(bounds.width, bounds.height));
    await window.setPosition(new PhysicalPosition(bounds.x, bounds.y));
  });
  return pending;
}
