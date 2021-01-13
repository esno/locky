set(LUKSD_SRC luksd.c core/sysfs.c)
add_executable(luksd ${LUKSD_SRC})

include_directories(./include)
