/*
 * Setup firebase-admin for use in nodejs
 * 1- Add the firebase-admin npm package.
 * 2- Go to https://console.firebase.google.com/ and create a project if you do not have an existing one.
 * 3- Get the secret from https://console.firebase.google.com/u/0/project/{PROJECT_ID}/settings/serviceaccounts/adminsdk.
 * 4- Set GOOGLE_APPLICATION_CREDENTIALS environment variable to the path of the JSON file.
 * 5- import the library using`import * as admin from 'firebase-admin'` in the server file.
 * 6- Call `admin.initializeApp()` in the server file to establish the connection.
 *
 * Reach out to @hadyrashwan <https://github.com/hadyrashwan> for questions on this community example.
 */

import admin from 'firebase-admin'; // eslint-disable-line import/no-unresolved

const undefinedFirestoreValue = 'custom.type.firestore'; // A work around as firestore does not support undefined.
const namePrefix = 'oidc_library';

const db = admin.firestore();
/**
 * Use the library with Google's Firestore database
 *
 * @class FirestoreAdapter
 */
class FirestoreAdapter {
  constructor(name) {
    this.name = `${namePrefix}_${name.split(' ').join('_')}`;
  }

  async upsert(id, payload, expiresIn) {
    let expiresAt;

    if (expiresIn) {
      expiresAt = new Date(Date.now() + expiresIn * 1000);
    }
    await db
      .collection(this.name)
      .doc(id)
      .set(
        {
          payload: this.updateNestedObject(payload, undefined, undefinedFirestoreValue),
          ...(expiresAt ? { expiresAt } : null),
        },
        { merge: true },
      );
  }

  async find(id) {
    const response = await db.collection(this.name).doc(id).get();
    if (!response.exists) {
      return undefined;
    }
    const data = response.data();
    return this.updateNestedObject(data.payload, undefinedFirestoreValue, undefined);
  }

  async findByUserCode(userCode) {
    const response = await db
      .collection(this.name)
      .where('payload.userCode', '==', userCode)
      .limit(1)
      .get();
    if (response.empty) {
      return undefined;
    }
    const data = response[0].data();
    return this.updateNestedObject(data.payload, undefinedFirestoreValue, undefined);
  }

  async findByUid(uid) {
    const response = await db.collection(this.name).where('payload.uid', '==', uid).limit(1).get();
    if (response.empty) {
      return undefined;
    }
    const data = response.docs[0].data();
    return this.updateNestedObject(data.payload, undefinedFirestoreValue, undefined);
  }

  async destroy(id) {
    await db.collection(this.name).doc(id).delete();
  }

  async revokeByGrantId(grantId) {
    const response = await db.collection(this.name).where('payload.grantId', '==', grantId).get();
    if (response.empty) {
      return;
    }
    const batch = db.batch();

    response.docs.forEach((doc) => batch.delete(db.collection(this.name).doc(doc.id).delete()));

    await batch.commit();
  }

  async consume(id) {
    const response = await db.collection(this.name).doc(id).get();
    if (!response.exists) {
      return;
    }
    const payload = response.data();
    payload.consumed = Math.floor(Date.now() / 1000);
    await db.collection(this.name).doc(id).update(payload);
  }

  /**
   * Replace a value in the object with another value
   *
   * @private
   * @param {object} internalObject
   * @param {(string | undefined)} value
   * @param {(string | undefined)} toReplaceValue
   * @returns
   * @memberof FirestoreAdapter
   */

  updateNestedObject(object, value, toReplaceValue) {
    const internalObject = Array.isArray(object) ? object : { ...object }; // avoid mutation
    const keys = Object.keys(internalObject);
    for (let index = 0; index < keys.length;) {
      const key = keys[index];
      if (Object.prototype.hasOwnProperty.call(internalObject, key)) {
        if (internalObject[key] === value) {
          internalObject[key] = toReplaceValue;
        }
        if (typeof internalObject[key] === 'object') {
          // Recursion
          internalObject[key] = this.updateNestedObject(internalObject[key], value, toReplaceValue);
        }
      }
      index += 1;
    }
    return internalObject;
  }
}
export default FirestoreAdapter;
