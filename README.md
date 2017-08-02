# project_by_sniffer

Проект разрабатывается в IDE CLion.

Для того, чтобы работать с библиотекой libcap:
apt-get install libcap

Чтобы CMake увидел libcap, был добавлен FindPCAP.cmake (на него ссылаемся в CMake строкой include(FindPCAP.cmake) )