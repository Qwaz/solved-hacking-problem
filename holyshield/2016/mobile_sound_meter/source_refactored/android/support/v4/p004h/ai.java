package android.support.v4.p004h;

import android.util.Log;
import android.view.LayoutInflater;
import android.view.LayoutInflater.Factory;
import android.view.LayoutInflater.Factory2;
import java.lang.reflect.Field;

/* renamed from: android.support.v4.h.ai */
class ai {
    private static Field f431a;
    private static boolean f432b;

    static void m847a(LayoutInflater layoutInflater, al alVar) {
        Factory2 ajVar = alVar != null ? new aj(alVar) : null;
        layoutInflater.setFactory2(ajVar);
        Factory factory = layoutInflater.getFactory();
        if (factory instanceof Factory2) {
            ai.m848a(layoutInflater, (Factory2) factory);
        } else {
            ai.m848a(layoutInflater, ajVar);
        }
    }

    static void m848a(LayoutInflater layoutInflater, Factory2 factory2) {
        if (!f432b) {
            try {
                f431a = LayoutInflater.class.getDeclaredField("mFactory2");
                f431a.setAccessible(true);
            } catch (Throwable e) {
                Log.e("LayoutInflaterCompatHC", "forceSetFactory2 Could not find field 'mFactory2' on class " + LayoutInflater.class.getName() + "; inflation may have unexpected results.", e);
            }
            f432b = true;
        }
        if (f431a != null) {
            try {
                f431a.set(layoutInflater, factory2);
            } catch (Throwable e2) {
                Log.e("LayoutInflaterCompatHC", "forceSetFactory2 could not set the Factory2 on LayoutInflater " + layoutInflater + "; inflation may have unexpected results.", e2);
            }
        }
    }
}
