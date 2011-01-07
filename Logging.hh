#ifndef LOGGING_HH__
#define LOGGING_HH__
#pragma once

#include <err.h>

#define ERROR_STDLIB(fmt, args...) err(1, fmt, ##args)
#define ERROR(fmt, args...) errx(1, fmt, ##args)
#define WARN(fmt, args...) warnx(fmt, ##args)

#endif
