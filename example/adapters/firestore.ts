// Setup firebase-admin for use in nodejs
// 1- Add the firebase-admin npm package.
// 2- Go to https://console.firebase.google.com/ and create a project if you do not have an existing one. And take note of the project ID .
// 3- Get the secret JSON file from https://console.firebase.google.com/u/0/project/{YOUR_PROJECT_ID}/settings/serviceaccounts/adminsdk.
// 4- Set the GOOGLE_APPLICATION_CREDENTIALS environment variable to equal the path of the service account JSON file.
// 5- import library   using`import * as admin from 'firebase-admin'` in the server file.
// 6- Call `admin.initializeApp()` in the server file to establish the connection. Make sure that it is called only once.

import * as admin from 'firebase-admin';

const db = admin.firestore();

/**
 * Use the library with Google's Firestore database
 *
 * @class FirestoreAdapter
 */
class FirestoreAdapter {
  public name: string;
  private undefinedFirestoreValue = 'custom.type.firestore'; // A work around as firestore does not support undefined.
  private namePrefix = 'oidc_library';
  constructor(name: string) {
    this.name = `${this.namePrefix}_${name.split(' ').join('_')}`;
  }

  public async upsert(id, payload, expiresIn) {
    try {
      let expiresAt;

      if (expiresIn) {
        expiresAt = new Date(Date.now() + expiresIn * 1000);
      }

      await db
        .collection(this.name)
        .doc(id)
        .set(
          {
            payload: this.updateNestedObject(
              payload,
              undefined,
              this.undefinedFirestoreValue
            ),
            ...(expiresAt ? { expiresAt } : null)
          },
          { merge: true }
        );
    } catch (e) {
      console.log(e);
    }
  }
  public async find(id) {
    const response = await db
      .collection(this.name)
      .doc(id)
      .get();

    if (!response.exists) {
      return undefined;
    }
    const data = response.data();
    return this.updateNestedObject(
      data.payload,
      this.undefinedFirestoreValue,
      undefined
    );
  }
  public async findByUserCode(userCode) {
    const response = await db
      .collection(this.name)
      .where('payload.userCode', '==', userCode)
      .limit(1)
      .get();

    if (response.empty) {
      return undefined;
    }
    const data = response[0].data();
    return this.updateNestedObject(
      data.payload,
      this.undefinedFirestoreValue,
      undefined
    );
  }

  public async findByUid(uid) {
    const response = await db
      .collection(this.name)
      .where('payload.uid', '==', uid)
      .limit(1)
      .get();

    if (response.empty) {
      return undefined;
    }
    const data = response.docs[0].data();
    return this.updateNestedObject(
      data.payload,
      this.undefinedFirestoreValue,
      undefined
    );
  }
  public async destroy(id) {
    await db
      .collection(this.name)
      .doc(id)
      .delete();
  }
  public async revokeByGrantId(grantId) {
    const response = await db
      .collection(this.name)
      .where('payload.grantId', '==', grantId)
      .get();
    for (const doc of response.docs) {
      await db
        .collection(this.name)
        .doc(doc.id)
        .delete();
    }
  }
  public async consume(id) {
    const response = await db
      .collection(this.name)
      .doc(id)
      .get();
    if (!response.exists) {
      return;
    }
    const payload = response.data();
    payload['consumed'] = Math.floor(Date.now() / 1000);

    await db
      .collection(this.name)
      .doc(id)
      .update(payload);
  }
  /**
   * Replace a value in the object with another value
   *
   * @private
   * @param {object} object
   * @param {(string | undefined)} value
   * @param {(string | undefined)} toReplaceValue
   * @returns
   * @memberof FirestoreAdapter
   */
  private updateNestedObject(
    object: object,
    value: string | undefined,
    toReplaceValue: string | undefined
  ) {
    for (const key in object) {
      if (Object.prototype.hasOwnProperty.call(object, key)) {
        if (object[key] === value) {
          object[key] = toReplaceValue;
          continue;
        }
        if (typeof object[key] === 'object') {
          // Recursion
          object[key] = this.updateNestedObject(
            object[key],
            value,
            toReplaceValue
          );
        }
      }
    }
    return object;
  }
}

export default FirestoreAdapter;
