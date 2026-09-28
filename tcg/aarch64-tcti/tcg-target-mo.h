/* SPDX-License-Identifier: MIT */
/*
 * Define target-specific memory model
 * Copyright (c) 2009, 2011 Stefan Weil
 */

#ifndef TCG_TARGET_MO_H
#define TCG_TARGET_MO_H

// We'll need to enforce memory ordering with barriers.
#define TCG_TARGET_DEFAULT_MO  (0)
 
#endif
