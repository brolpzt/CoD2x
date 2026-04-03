#ifndef SCREENSHOT_H
#define SCREENSHOT_H

void screenshot_init();
void screenshot_unload();

/** Chamado no fim do desenho 2D (drawing_end). */
void screenshot_on_drawing_end();

/** Agenda captura no próximo drawing_end e envio JPEG ao servidor (servidor: getss -> `| takeScreenshot`). */
void screenshot_schedule_capture(void);

#endif
