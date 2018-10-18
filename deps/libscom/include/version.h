//
// Created by sven on 9/29/18.
//

#ifndef LIBSCOM_VERSION_H
#define LIBSCOM_VERSION_H

// major version of LIBSCOM in integer
#define LIBSCOM_MAJOR_VERSION 0
// minor version of LIBSCOM in integer
#define LIBSCOM_MINOR_VERSION 1
// patch version of LIBSCOM in integer
#define LIBSCOM_PATCH_VERSION 1

// version of LIBSCOM in "<major>.<minor>.<patch>" string format.
#define LIBSCOM_STRINGIFY(x) LIBSCOM_DO_STRINGIFY(x)
#define LIBSCOM_DO_STRINGIFY(x) #x
#define LIBSCOM_VERSION \
  LIBSCOM_STRINGIFY(LIBSCOM_MAJOR_VERSION.LIBSCOM_MINOR_VERSION.LIBSCOM_PATCH_VERSION)

// version of LIBSCOM in integer format.
#define LIBSCOM_VERSION_INT \
  (LIBSCOM_MAJOR_VERSION * 10000 + LIBSCOM_MINOR_VERSION * 100 + LIBSCOM_PATCH_VERSION)


#endif //LIBSCOM_VERSION_H
