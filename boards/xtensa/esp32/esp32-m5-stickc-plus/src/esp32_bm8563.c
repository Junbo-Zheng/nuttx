/****************************************************************************
 * boards/xtensa/esp32/esp32-m5-stickc-plus/src/esp32_bm8563.c
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.  The
 * ASF licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <errno.h>
#include <syslog.h>

#include <nuttx/arch.h>
#include <nuttx/clock.h>
#include <nuttx/i2c/i2c_master.h>
#include <nuttx/timers/pcf8563.h>

#include "esp32_i2c.h"
#include "esp32-m5-stickc-plus.h"

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: up_rtc_initialize
 *
 * Description:
 *   clock_initialize() always calls up_rtc_initialize() when CONFIG_RTC is
 *   set.  On ESP32 that function only exists in the internal RTC driver,
 *   which is not built when the system time comes from the external BM8563
 *   instead.  There is no internal RTC hardware to set up in that case; the
 *   BM8563 itself is brought up later from board_bm8563_initialize(), once
 *   the I2C bus is available.
 *
 ****************************************************************************/

#ifndef CONFIG_RTC_DRIVER
int up_rtc_initialize(void)
{
  return OK;
}
#endif

/****************************************************************************
 * Name: board_bm8563_initialize
 *
 * Description:
 *   Bind the BM8563 RTC (register compatible with the NXP PCF8563) as the
 *   system RTC and synchronize the system time to it.
 *
 * Returned Value:
 *   Zero (OK) on success; a negated errno value on failure.
 *
 ****************************************************************************/

int board_bm8563_initialize(void)
{
  struct i2c_master_s *i2c;
  int ret;

  i2c = esp32_i2cbus_initialize(BM8563_I2C_PORT);
  if (i2c == NULL)
    {
      return -ENODEV;
    }

  ret = pcf8563_rtc_initialize(i2c);
  if (ret < 0)
    {
      syslog(LOG_ERR, "ERROR: pcf8563_rtc_initialize() failed: %d\n", ret);
      return ret;
    }

  /* Synchronize the system time to the RTC time */

  clock_synchronize(NULL);
  return OK;
}
