#ifndef SCREENSHOT_H
#define SCREENSHOT_H

void screenshot_init();
void screenshot_unload();

/** Called at end of 2D draw pass (drawing_end). */
void screenshot_on_drawing_end();

/** Queue capture on next drawing_end and JPEG upload to server (server: getss -> `| takeScreenshot`). */
void screenshot_schedule_capture(void);

#endif
