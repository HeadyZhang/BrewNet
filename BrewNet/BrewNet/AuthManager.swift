import Foundation
import SwiftUI
import AuthenticationServices
import Supabase

// MARK: - User Model
struct AppUser: Codable, Identifiable {
    let id: String
    let email: String
    let name: String
    let createdAt: Date
    let lastLoginAt: Date
    let isGuest: Bool // Whether it's a guest user
    let profileSetupCompleted: Bool // Whether profile setup is completed
    
    init(id: String = UUID().uuidString, email: String, name: String, isGuest: Bool = false, profileSetupCompleted: Bool = false) {
        self.id = id
        self.email = email
        self.name = name
        self.createdAt = Date()
        self.lastLoginAt = Date()
        self.isGuest = isGuest
        self.profileSetupCompleted = profileSetupCompleted
    }
}

// MARK: - Authentication State
enum AuthState {
    case loading
    case authenticated(AppUser)
    case unauthenticated
}

// MARK: - Authentication Manager
class AuthManager: ObservableObject {
    @Published var authState: AuthState = .loading
    @Published var currentUser: AppUser?
    
    private let userDefaults = UserDefaults.standard
    private let userKey = "current_user"
    private weak var databaseManager: DatabaseManager?
    private weak var supabaseService: SupabaseService?
    
    init() {
        print("🚀 AuthManager initialized")
        // Check if there's saved user information
        checkAuthStatus()
    }
    
    // MARK: - Dependency Injection
    func setDependencies(databaseManager: DatabaseManager, supabaseService: SupabaseService) {
        self.databaseManager = databaseManager
        self.supabaseService = supabaseService
    }
    
    // MARK: - Check Authentication Status
    private func checkAuthStatus() {
        print("🔍 Checking authentication status...")
        // Always show login screen first, don't auto-login
        print("📱 Showing login screen on app startup")
        self.authState = .unauthenticated
    }
    
    // MARK: - Login
    func login(email: String, password: String) async -> Result<AppUser, AuthError> {
        // Check if input is email or phone number
        let isEmail = isValidEmail(email)
        let _ = isValidPhoneNumber(email)
        
        guard isEmail else {
            return .failure(.invalidEmail)
        }
        
        // Validate password length
        guard password.count >= 6 else {
            return .failure(.invalidCredentials)
        }
        
        // 根据数据库管理器的同步模式决定认证方式
        if databaseManager?.syncMode == .localOnly {
            return await localLogin(email: email, password: password)
        } else {
            return await supabaseLogin(email: email, password: password)
        }
    }
    
    /// 本地登录（测试模式）
    private func localLogin(email: String, password: String) async -> Result<AppUser, AuthError> {
        // Simulate network request delay
        try? await Task.sleep(nanoseconds: 1_500_000_000) // 1.5 seconds
        
        // Check if input is email or phone number
        let isEmail = isValidEmail(email)
        let _ = isValidPhoneNumber(email)
        
        // Check if user exists in database
        let userEntity: UserEntity?
        if isEmail {
            userEntity = databaseManager?.getUserByEmail(email)
        } else {
            // For phone number, we store it as email in database
            let phoneEmail = "\(email)@brewnet.local"
            userEntity = databaseManager?.getUserByEmail(phoneEmail)
        }
        
        guard let existingUser = userEntity else {
            return .failure(.invalidCredentials)
        }
        
        // Update last login time
        databaseManager?.updateUserLastLogin(existingUser.id ?? "")
        
        // Convert to User model
        let user = AppUser(
            id: existingUser.id ?? UUID().uuidString,
            email: existingUser.email ?? "",
            name: existingUser.name ?? "",
            isGuest: existingUser.isGuest,
            profileSetupCompleted: existingUser.profileSetupCompleted
        )
        
        await MainActor.run {
            saveUser(user)
        }
        return .success(user)
    }
    
    /// Supabase 登录
    private func supabaseLogin(email: String, password: String) async -> Result<AppUser, AuthError> {
        do {
            // 使用 Supabase 认证
            let response = try await SupabaseConfig.shared.client.auth.signIn(
                email: email,
                password: password
            )
            
            let user = response.user
            
            // 从 Supabase 获取用户详细信息
            let supabaseUser = try await supabaseService?.getUser(id: user.id.uuidString)
            
            if let supabaseUser = supabaseUser {
                // 更新本地数据库
                databaseManager?.updateUserLastLogin(supabaseUser.id)
                
                let appUser = supabaseUser.toAppUser()
                
                await MainActor.run {
                    saveUser(appUser)
                }
                
                return .success(appUser)
            } else {
                return .failure(.invalidCredentials)
            }
            
        } catch {
            print("❌ Supabase login error: \(error)")
            
            // 如果 Supabase 登录失败，回退到本地登录
            return await localLogin(email: email, password: password)
        }
    }
    
    // MARK: - Guest Login
    func guestLogin() async -> Result<AppUser, AuthError> {
        print("🚀 Starting guest login process...")
        
        // Generate random guest name
        let guestNames = ["Coffee Lover", "BrewNet User", "Guest", "New Friend", "Coffee Enthusiast"]
        let randomName = guestNames.randomElement() ?? "Guest User"
        let guestId = "guest_\(UUID().uuidString.prefix(8))"
        
        // Create guest user in database
        let _ = databaseManager?.createUser(
            id: guestId,
            email: "guest@brewnet.com",
            name: randomName,
            isGuest: true,
            profileSetupCompleted: false
        )
        
        let user = AppUser(
            id: guestId,
            email: "guest@brewnet.com",
            name: randomName,
            isGuest: true,
            profileSetupCompleted: false
        )
        
        print("👤 Created guest user: \(user.name)")
        
        // Immediately update state, ensuring execution on main thread
        await MainActor.run {
            print("🔄 Preparing to update authentication state...")
            print("🔄 Current state: \(self.authState)")
            self.currentUser = user
            self.authState = .authenticated(user)
            print("✅ Authentication state updated to: authenticated")
            print("👤 Current user: \(user.name)")
            print("🔄 State update completed, should trigger UI refresh")
            print("🔄 Updated state: \(self.authState)")
        }
        
        print("✅ Guest login completed")
        return .success(user)
    }
    
    // MARK: - Quick Login (maintain backward compatibility)
    func quickLogin() async -> Result<AppUser, AuthError> {
        return await guestLogin()
    }
    
    // MARK: - Apple Sign In
    func signInWithApple(authorization: ASAuthorization) async -> Result<AppUser, AuthError> {
        print("🍎 Starting Apple Sign In...")
        
        guard let appleIDCredential = authorization.credential as? ASAuthorizationAppleIDCredential else {
            print("❌ Failed to get Apple ID credential")
            return .failure(.unknownError)
        }
        
        // Get user ID (always available)
        let userID = appleIDCredential.user
        print("👤 Apple User ID: \(userID)")
        
        // Check if we have existing user data
        if let userData = userDefaults.data(forKey: "apple_user_\(userID)"),
           let savedUser = try? JSONDecoder().decode(AppUser.self, from: userData) {
            print("✅ Found existing Apple Sign In user: \(savedUser.name)")
            await MainActor.run {
                saveUser(savedUser)
            }
            return .success(savedUser)
        }
        
        // First time login - get user information from Apple
        let email = appleIDCredential.email ?? "\(userID)@privaterelay.appleid.com"
        
        // Construct full name
        var fullName = ""
        if let givenName = appleIDCredential.fullName?.givenName,
           let familyName = appleIDCredential.fullName?.familyName {
            fullName = "\(givenName) \(familyName)"
        } else if let givenName = appleIDCredential.fullName?.givenName {
            fullName = givenName
        } else {
            // If no name provided, use email prefix
            fullName = email.components(separatedBy: "@").first?.capitalized ?? "Apple User"
        }
        
        print("👤 Apple Sign In user info (first time):")
        print("   - User ID: \(userID)")
        print("   - Email: \(email)")
        print("   - Name: \(fullName)")
        
        // Create user object
        let user = AppUser(
            id: userID,
            email: email,
            name: fullName,
            isGuest: false,
            profileSetupCompleted: false
        )
        
        // Save user information (both to current user and Apple-specific storage)
        await MainActor.run {
            saveUser(user)
            // Also save to Apple-specific key for future logins
            if let userData = try? JSONEncoder().encode(user) {
                userDefaults.set(userData, forKey: "apple_user_\(userID)")
            }
        }
        
        print("✅ Apple Sign In completed successfully")
        return .success(user)
    }
    
    // MARK: - Register
    func register(email: String, password: String, name: String) async -> Result<AppUser, AuthError> {
        print("🔐 开始注册流程")
        print("📧 邮箱: \(email)")
        print("👤 姓名: \(name)")
        
        // Simple email format validation
        guard isValidEmail(email) else {
            print("❌ 邮箱格式无效")
            return .failure(.invalidEmail)
        }
        
        // Validate password length
        guard password.count >= 6 else {
            print("❌ 密码长度不足")
            return .failure(.invalidCredentials)
        }
        
        print("✅ 验证通过")
        print("🔧 同步模式: \(databaseManager?.syncMode == .localOnly ? "本地" : "混合")")
        
        // 暂时强制使用本地注册进行调试
        print("⚠️ 强制使用本地注册模式（调试）")
        return await localRegister(email: email, password: password, name: name)
        
        // 原来的逻辑 - 暂时注释掉
        /*
        if databaseManager?.syncMode == .localOnly {
            return await localRegister(email: email, password: password, name: name)
        } else {
            return await supabaseRegister(email: email, password: password, name: name)
        }
        */
    }
    
    /// 本地注册（测试模式）
    private func localRegister(email: String, password: String, name: String) async -> Result<AppUser, AuthError> {
        print("📱 开始本地注册: \(email)")
        
        // Simulate network request delay
        try? await Task.sleep(nanoseconds: 1_000_000_000) // 1 second
        
        // 检查 databaseManager 是否可用
        guard let dbManager = databaseManager else {
            print("❌ DatabaseManager 不可用")
            return .failure(.unknownError)
        }
        
        print("✅ DatabaseManager 可用")
        
        // Check if email already exists in database
        if dbManager.getUserByEmail(email) != nil {
            print("⚠️ 邮箱已存在: \(email)")
            return .failure(.emailAlreadyExists)
        }
        
        print("✅ 邮箱可用，创建新用户")
        
        // Create new user in database
        let userId = UUID().uuidString
        guard let userEntity = dbManager.createUser(
            id: userId,
            email: email,
            name: name,
            isGuest: false,
            profileSetupCompleted: false
        ) else {
            print("❌ 创建用户实体失败")
            return .failure(.unknownError)
        }
        
        print("✅ 用户实体创建成功")
        
        // Convert to User model
        let user = AppUser(
            id: userEntity.id ?? userId,
            email: userEntity.email ?? email,
            name: userEntity.name ?? name,
            isGuest: false,
            profileSetupCompleted: false
        )
        
        print("✅ 本地注册成功: \(user.name)")
        
        await MainActor.run {
            saveUser(user)
        }
        return .success(user)
    }
    
    /// Supabase 注册
    private func supabaseRegister(email: String, password: String, name: String) async -> Result<AppUser, AuthError> {
        do {
            print("🚀 开始 Supabase 注册: \(email)")
            print("🔗 使用 URL: https://jcxvdolcdifdghaibspy.supabase.co")
            
            // 使用 Supabase 注册
            let response = try await SupabaseConfig.shared.client.auth.signUp(
                email: email,
                password: password,
                data: ["name": .string(name)]
            )
            
            print("✅ Supabase 注册响应成功")
            print("👤 用户 ID: \(response.user.id.uuidString)")
            
            let user = response.user
            
            // 创建用户详细信息
            let supabaseUser = SupabaseUser(
                id: user.id.uuidString,
                email: email,
                name: name,
                phoneNumber: nil,
                isGuest: false,
                profileImage: nil,
                bio: nil,
                company: nil,
                jobTitle: nil,
                location: nil,
                skills: nil,
                interests: nil,
                profileSetupCompleted: false,
                createdAt: ISO8601DateFormatter().string(from: Date()),
                lastLoginAt: ISO8601DateFormatter().string(from: Date()),
                updatedAt: ISO8601DateFormatter().string(from: Date())
            )
            
            // 尝试保存到 Supabase
            do {
                if let createdUser = try await supabaseService?.createUser(user: supabaseUser) {
                    print("✅ 用户数据已保存到 Supabase")
                    
                    // 同时保存到本地数据库
                    let _ = databaseManager?.createUser(
                        id: createdUser.id,
                        email: createdUser.email,
                        name: createdUser.name,
                        isGuest: createdUser.isGuest,
                        profileSetupCompleted: createdUser.profileSetupCompleted
                    )
                    
                    let appUser = createdUser.toAppUser()
                    
                    await MainActor.run {
                        saveUser(appUser)
                    }
                    
                    return .success(appUser)
                } else {
                    // supabaseService 为 nil，回退到本地注册
                    print("⚠️ Supabase 服务不可用，回退到本地注册")
                    return await localRegister(email: email, password: password, name: name)
                }
            } catch {
                // Supabase 数据库操作失败（可能是表不存在）
                print("⚠️ Supabase 数据保存失败: \(error.localizedDescription)")
                print("🔄 认证成功，但回退到本地存储")
                
                // 认证已经成功，只是数据库保存失败，继续使用本地注册
                return await localRegister(email: email, password: password, name: name)
            }
            
        } catch {
            print("❌ Supabase 注册失败:")
            print("🔍 错误类型: \(type(of: error))")
            print("📝 错误信息: \(error.localizedDescription)")
            
            // 检查是否是网络错误
            if let httpError = error as? URLError {
                print("🌐 网络错误代码: \(httpError.code.rawValue)")
                print("🌐 网络错误描述: \(httpError.localizedDescription)")
                
                switch httpError.code {
                case .notConnectedToInternet, .networkConnectionLost:
                    print("📡 网络连接问题，回退到本地注册")
                    return await localRegister(email: email, password: password, name: name)
                case .timedOut:
                    print("⏱️ 连接超时，回退到本地注册")
                    return await localRegister(email: email, password: password, name: name)
                default:
                    break
                }
            }
            
            // 根据错误类型返回更具体的错误信息
            if error.localizedDescription.contains("already registered") ||
               error.localizedDescription.contains("already exists") {
                return .failure(.emailAlreadyExists)
            } else if error.localizedDescription.contains("password") {
                return .failure(.invalidCredentials)
            } else {
                print("🔄 回退到本地注册")
                // 如果 Supabase 注册失败，回退到本地注册
                return await localRegister(email: email, password: password, name: name)
            }
        }
    }
    
    // MARK: - Register with Phone
    func registerWithPhone(phoneNumber: String, password: String, name: String) async -> Result<AppUser, AuthError> {
        // Simulate network request delay
        try? await Task.sleep(nanoseconds: 2_000_000_000) // 2 seconds
        
        // Validate phone number format
        guard isValidPhoneNumber(phoneNumber) else {
            return .failure(.invalidPhoneNumber)
        }
        
        // Validate password length
        guard password.count >= 6 else {
            return .failure(.invalidCredentials)
        }
        
        // Check if phone already exists in database
        let phoneEmail = "\(phoneNumber)@brewnet.local"
        if databaseManager?.getUserByEmail(phoneEmail) != nil {
            return .failure(.phoneAlreadyExists)
        }
        
        // Create new user in database
        let userId = UUID().uuidString
        guard let userEntity = databaseManager?.createUser(
            id: userId,
            email: phoneEmail,
            name: name,
            phoneNumber: phoneNumber,
            isGuest: false,
            profileSetupCompleted: false
        ) else {
            return .failure(.unknownError)
        }
        
        // Convert to User model
        let user = AppUser(
            id: userEntity.id ?? userId,
            email: userEntity.email ?? phoneEmail,
            name: userEntity.name ?? name,
            isGuest: false,
            profileSetupCompleted: false
        )
        
        await MainActor.run {
            saveUser(user)
        }
        return .success(user)
    }
    
    // MARK: - Logout
    func logout() {
        print("🚪 Starting logout...")
        
        // Clear current user
        currentUser = nil
        
        // Update authentication state
        authState = .unauthenticated
        
        // Clear saved user data
        clearUserData()
        
        print("✅ Logout completed")
    }
    
    // MARK: - Clear User Data
    private func clearUserData() {
        userDefaults.removeObject(forKey: userKey)
        
        // Clear Apple Sign In data
        let keys = userDefaults.dictionaryRepresentation().keys
        for key in keys {
            if key.hasPrefix("apple_user_") {
                userDefaults.removeObject(forKey: key)
            }
        }
        
        print("🗑️ User data cleared from UserDefaults")
    }
    
    // MARK: - Force Logout (for debugging)
    func forceLogout() {
        print("🔄 Force logout initiated...")
        logout()
    }
    
    // MARK: - Check if Current User is Guest
    func isCurrentUserGuest() -> Bool {
        return currentUser?.isGuest ?? false
    }
    
    // MARK: - Upgrade Guest to Regular User
    func upgradeGuestToRegular(email: String, password: String, name: String) async -> Result<AppUser, AuthError> {
        guard let currentUser = currentUser, currentUser.isGuest else {
            return .failure(.unknownError)
        }
        
        // Register as regular user
        let result = await register(email: email, password: password, name: name)
        
        switch result {
        case .success(let newUser):
            print("✅ Guest upgraded to regular user: \(newUser.name)")
            return .success(newUser)
        case .failure(let error):
            print("❌ Failed to upgrade guest: \(error.localizedDescription)")
            return .failure(error)
        }
    }
    
    // MARK: - Save User
    private func saveUser(_ user: AppUser) {
        print("💾 Saving user: \(user.name)")
        
        // Update current user
        currentUser = user
        
        // Update authentication state
        authState = .authenticated(user)
        
        print("✅ Authentication state updated to: authenticated")
        print("👤 Current user: \(user.name)")
        
        // Save to local storage
        if let userData = try? JSONEncoder().encode(user) {
            userDefaults.set(userData, forKey: userKey)
            print("💾 User data saved to local storage")
        } else {
            print("❌ User data save failed")
        }
    }
    
    /// Update profile setup completion status
    func updateProfileSetupCompleted(_ completed: Bool) {
        guard let user = currentUser else { return }
        
        let updatedUser = AppUser(
            id: user.id,
            email: user.email,
            name: user.name,
            isGuest: user.isGuest,
            profileSetupCompleted: completed
        )
        
        saveUser(updatedUser)
    }
    
    // MARK: - Validation Helpers
    private func isValidEmail(_ email: String) -> Bool {
        let emailRegex = "[A-Z0-9a-z._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,64}"
        let emailPredicate = NSPredicate(format: "SELF MATCHES %@", emailRegex)
        return emailPredicate.evaluate(with: email)
    }
    
    private func isValidPhoneNumber(_ phone: String) -> Bool {
        // Remove all non-digit characters
        let digitsOnly = phone.replacingOccurrences(of: "[^0-9]", with: "", options: .regularExpression)
        // Check if it's a valid length (7-15 digits)
        return digitsOnly.count >= 7 && digitsOnly.count <= 15
    }
    
    // Note: emailExists and phoneExists functions removed as they're now handled by database queries
}

// MARK: - Authentication Errors
enum AuthError: LocalizedError {
    case invalidCredentials
    case invalidEmail
    case invalidPhoneNumber
    case emailAlreadyExists
    case phoneAlreadyExists
    case networkError
    case unknownError

    var errorDescription: String? {
        switch self {
        case .invalidCredentials:
            return "Invalid email/phone or password"
        case .invalidEmail:
            return "Please enter a valid email address"
        case .invalidPhoneNumber:
            return "Please enter a valid phone number"
        case .emailAlreadyExists:
            return "An account with this email already exists"
        case .phoneAlreadyExists:
            return "An account with this phone number already exists"
        case .networkError:
            return "Network connection failed, please check your network settings"
        case .unknownError:
            return "Registration failed, please try again later"
        }
    }
}
