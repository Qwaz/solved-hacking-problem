package android.support.v4.p004h.p013a;

import android.os.Bundle;
import android.view.accessibility.AccessibilityNodeInfo;
import android.view.accessibility.AccessibilityNodeProvider;
import java.util.List;

/* renamed from: android.support.v4.h.a.ac */
final class ac extends AccessibilityNodeProvider {
    final /* synthetic */ ad f414a;

    ac(ad adVar) {
        this.f414a = adVar;
    }

    public AccessibilityNodeInfo createAccessibilityNodeInfo(int i) {
        return (AccessibilityNodeInfo) this.f414a.m672a(i);
    }

    public List findAccessibilityNodeInfosByText(String str, int i) {
        return this.f414a.m673a(str, i);
    }

    public AccessibilityNodeInfo findFocus(int i) {
        return (AccessibilityNodeInfo) this.f414a.m675b(i);
    }

    public boolean performAction(int i, int i2, Bundle bundle) {
        return this.f414a.m674a(i, i2, bundle);
    }
}
