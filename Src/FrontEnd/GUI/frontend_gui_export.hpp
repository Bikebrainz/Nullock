#pragma once

#include <QtGlobal>

#if defined(FRONTEND_GUI_LIBRARY)
#define FRONTEND_GUI_EXPORT Q_DECL_EXPORT
#else
#define FRONTEND_GUI_EXPORT Q_DECL_IMPORT
#endif
