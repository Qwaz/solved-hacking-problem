package android.support.v7.p014a;

import android.content.Context;
import android.location.Location;
import android.location.LocationManager;
import android.support.v4.p002b.C0061n;
import android.util.Log;
import java.util.Calendar;

/* renamed from: android.support.v7.a.ba */
class ba {
    private static final bc f680a;
    private final Context f681b;
    private final LocationManager f682c;

    static {
        f680a = new bc();
    }

    ba(Context context) {
        this.f681b = context;
        this.f682c = (LocationManager) context.getSystemService("location");
    }

    private Location m1816a(String str) {
        if (this.f682c != null) {
            try {
                if (this.f682c.isProviderEnabled(str)) {
                    return this.f682c.getLastKnownLocation(str);
                }
            } catch (Throwable e) {
                Log.d("TwilightManager", "Failed to get last known location", e);
            }
        }
        return null;
    }

    private void m1817a(Location location) {
        long j;
        bc bcVar = f680a;
        long currentTimeMillis = System.currentTimeMillis();
        az a = az.m1814a();
        a.m1815a(currentTimeMillis - 86400000, location.getLatitude(), location.getLongitude());
        long j2 = a.f676a;
        a.m1815a(currentTimeMillis, location.getLatitude(), location.getLongitude());
        boolean z = a.f678c == 1;
        long j3 = a.f677b;
        long j4 = a.f676a;
        a.m1815a(86400000 + currentTimeMillis, location.getLatitude(), location.getLongitude());
        long j5 = a.f677b;
        if (j3 == -1 || j4 == -1) {
            j = 43200000 + currentTimeMillis;
        } else {
            j = currentTimeMillis > j4 ? 0 + j5 : currentTimeMillis > j3 ? 0 + j4 : 0 + j3;
            j += 60000;
        }
        bcVar.f683a = z;
        bcVar.f684b = j2;
        bcVar.f685c = j3;
        bcVar.f686d = j4;
        bcVar.f687e = j5;
        bcVar.f688f = j;
    }

    private boolean m1818a(bc bcVar) {
        return bcVar != null && bcVar.f688f > System.currentTimeMillis();
    }

    private Location m1819b() {
        Location location = null;
        Location a = C0061n.m452a(this.f681b, "android.permission.ACCESS_COARSE_LOCATION") == 0 ? m1816a("network") : null;
        if (C0061n.m452a(this.f681b, "android.permission.ACCESS_FINE_LOCATION") == 0) {
            location = m1816a("gps");
        }
        if (location != null && a != null) {
            return location.getTime() > a.getTime() ? location : a;
        } else {
            if (location == null) {
                location = a;
            }
            return location;
        }
    }

    boolean m1820a() {
        bc bcVar = f680a;
        if (m1818a(bcVar)) {
            return bcVar.f683a;
        }
        Location b = m1819b();
        if (b != null) {
            m1817a(b);
            return bcVar.f683a;
        }
        Log.i("TwilightManager", "Could not get last known location. This is probably because the app does not have any location permissions. Falling back to hardcoded sunrise/sunset values.");
        int i = Calendar.getInstance().get(11);
        return i < 6 || i >= 22;
    }
}
