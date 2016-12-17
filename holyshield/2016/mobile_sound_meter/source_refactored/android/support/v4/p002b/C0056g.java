package android.support.v4.p002b;

import android.content.ComponentName;
import android.content.Intent;

/* renamed from: android.support.v4.b.g */
class C0056g implements C0055f {
    C0056g() {
    }

    public Intent m437a(ComponentName componentName) {
        Intent intent = new Intent("android.intent.action.MAIN");
        intent.setComponent(componentName);
        intent.addCategory("android.intent.category.LAUNCHER");
        return intent;
    }
}
