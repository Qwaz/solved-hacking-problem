package android.support.v7.widget;

import android.content.ComponentName;
import java.math.BigDecimal;

public final class ad {
    public final ComponentName f1274a;
    public final long f1275b;
    public final float f1276c;

    public ad(ComponentName componentName, long j, float f) {
        this.f1274a = componentName;
        this.f1275b = j;
        this.f1276c = f;
    }

    public ad(String str, long j, float f) {
        this(ComponentName.unflattenFromString(str), j, f);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        ad adVar = (ad) obj;
        if (this.f1274a == null) {
            if (adVar.f1274a != null) {
                return false;
            }
        } else if (!this.f1274a.equals(adVar.f1274a)) {
            return false;
        }
        return this.f1275b != adVar.f1275b ? false : Float.floatToIntBits(this.f1276c) == Float.floatToIntBits(adVar.f1276c);
    }

    public int hashCode() {
        return (((((this.f1274a == null ? 0 : this.f1274a.hashCode()) + 31) * 31) + ((int) (this.f1275b ^ (this.f1275b >>> 32)))) * 31) + Float.floatToIntBits(this.f1276c);
    }

    public String toString() {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("[");
        stringBuilder.append("; activity:").append(this.f1274a);
        stringBuilder.append("; time:").append(this.f1275b);
        stringBuilder.append("; weight:").append(new BigDecimal((double) this.f1276c));
        stringBuilder.append("]");
        return stringBuilder.toString();
    }
}
