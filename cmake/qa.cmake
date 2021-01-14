if (QA)
  set(CMAKE_VERBOSE_MAKEFILE ON)

  if (CMAKE_COMPILER_IS_GNUCC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wfloat-equal -Wshadow -Wstrict-prototypes -Wstrict-overflow=5")
  endif ()
endif ()

if (QA_FULL)
  if (CMAKE_COMPILER_IS_GNUCC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wcast-qual -Wconversion -Wunreachable-code")
  endif ()
endif ()

if (QA_FULLER)
  if (CMAKE_COMPILER_IS_GNUCC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fanalyzer")
  endif ()
endif ()
