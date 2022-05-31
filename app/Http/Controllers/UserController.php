<?php

namespace App\Http\Controllers;

use App\Http\Requests\StoreUserRequest;
use App\Http\Resources\UserResource;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Storage;

class UserController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['index', 'login', 'register']]);
    }


    public function register(StoreUserRequest $request)
    {

        $user =  User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        if (!$user) {
            return response()->json(['errors' => ['email' => 'Bad Request']], 400);
        }


        return response()->json(['success' => 'Registration Successful'], 201);
    }

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request)
    {
        $user = User::where('email', $request->email)->first();

        if (!$user || !Hash::check($request->password, $user->getAuthPassword())) {
            return response()->json(['errors' => ['email' => "These credentials do not match our records."]], 403);
        }

        if (!$token = auth()->attempt(['email' => $user->email, 'password' => $request->password])) {
            return response()->json(['errors' => ['email' => "Unauthorized"]], 401);
        }

        return $this->respondWithToken($token);
    }

    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me()
    {
        return response()->json(auth()->user());
    }

    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        auth()->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        return $this->respondWithToken(auth()->refresh());
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60
        ]);
    }
    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index()
    {
        return UserResource::collection(User::all());
    }



    /**
     * Store a newly created resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function store(Request $request)
    {
        //
    }

    /**
     * Display the specified resource.
     *
     * @param  \App\Models\User  $user
     * @return \Illuminate\Http\Response
     */
    public function show(User $user)
    {
        //
    }

    /**
     * Update the specified resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \App\Models\User  $user
     * @return \Illuminate\Http\Response
     */


    public function update(Request $request)
    {
        // return $request->all();
        // $avatar_path =  auth()->user()->avatar ?? "d.png";
        // $pathinfo = pathinfo($avatar_path);
        // $userAvatar = $pathinfo['filename'] . '.' . $pathinfo['extension'];
        $userAvatar = null;
        if ($request->hasFile('avatar')) {



            // if ($userAvatar && $userAvatar != "avatar.jpg") {
            //     Storage::delete('public/avatar/' . $userAvatar);
            // }

            $file = $request->file("avatar");

            $giveAvatarName = time() . "-" . $file->getClientOriginalName();
            Storage::put($giveAvatarName, $file);
            Storage::move($giveAvatarName, 'public/avatar/' . $giveAvatarName);
            $userAvatar = $giveAvatarName;
        }

        auth()->user()->update([
            'avatar' =>  $userAvatar,
        ]);





        return  response()->json(null, 200);
    }

    /**
     * Remove the specified resource from storage.
     *
     * @param  \App\Models\User  $user
     * @return \Illuminate\Http\Response
     */
    public function destroy(User $user)
    {
        //
    }
}
