option(QA "enable quality assurance" OFF)
option(QA_FULL "enable quality assurance (detailed compiler warnings)" OFF)
option(QA_FULLER "enable quality assurance (static code analysis)" OFF)

if (QA_FULL OR QA_FULLER)
  set(QA ON)
  set(QA_FULL ON)
endif ()
