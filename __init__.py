# -*- coding: utf-8 -*-
# ***************************************************************************
# __init__.py  -  Google Earth Engine Authenticator
# ***************************************************************************
# *                                                                         *
# *   This program is free software; you can redistribute it and/or modify  *
# *   it under the terms of the GNU General Public License as published by  *
# *   the Free Software Foundation; either version 2 of the License, or     *
# *   (at your option) any later version.                                   *
# *                                                                         *
# ***************************************************************************

def classFactory(iface):
  from .gee_auth import GEE_auth_Plugin
  return GEE_auth_Plugin(iface)
