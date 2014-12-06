#ifndef _NGHTTP2_WINDOWS_H_
#define _NGHTTP2_WINDOWS_H_

#include <WinSock2.h>

#ifndef _SSIZE_T
#define _SSIZE_T

/* posix defines ssize_t as used for byte count and error indication.
 * it is not part of the C standard and missing in Visual Studio.
 */
typedef long ssize_t;
#endif /* _SSIZE_T */

#ifndef _ATTRIBUTE_UNUSED
#define _ATTRIBUTE_UNUSED
#define _U_
#endif

#endif /* _NGHTTP2_WINDOWS_H_ */