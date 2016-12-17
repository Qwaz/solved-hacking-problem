package android.support.v4.p004h.p013a;

import android.os.Bundle;
import android.view.accessibility.AccessibilityNodeInfo;
import android.view.accessibility.AccessibilityNodeProvider;
import java.util.List;

/* renamed from: android.support.v4.h.a.z */
final class C0146z extends AccessibilityNodeProvider {
    final /* synthetic */ aa f425a;

    C0146z(aa aaVar) {
        this.f425a = aaVar;
    }

    public AccessibilityNodeInfo createAccessibilityNodeInfo(int i) {
        return (AccessibilityNodeInfo) this.f425a.m668a(i);
    }

    public List findAccessibilityNodeInfosByText(String str, int i) {
        return this.f425a.m669a(str, i);
    }

    public boolean performAction(int i, int i2, Bundle bundle) {
        return this.f425a.m670a(i, i2, bundle);
    }
}
